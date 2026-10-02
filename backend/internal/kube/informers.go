package kube

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	appslisters "k8s.io/client-go/listers/apps/v1"
	batchlisters "k8s.io/client-go/listers/batch/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// ResourceEvent is the normalized shape pushed over the WS feed. It covers
// both informer lifecycle events (verb = added/updated/deleted) and native
// corev1.Event objects (verb = "event" with Reason/Message populated).
type ResourceEvent struct {
	Verb         string    `json:"verb"`
	Kind         string    `json:"kind"`
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	At           time.Time `json:"at"`
	Reason       string    `json:"reason,omitempty"`
	Message      string    `json:"message,omitempty"`
	Type         string    `json:"type,omitempty"`
	InvolvedKind string    `json:"involvedKind,omitempty"`
	InvolvedName string    `json:"involvedName,omitempty"`
}

type eventSubscriber struct {
	id int
	ns string
	ch chan ResourceEvent
}

// Subscription is the handle returned to callers; close via EventBus.Unsubscribe.
type Subscription struct {
	sub *eventSubscriber
	bus *EventBus
}

// Chan returns the receive-only channel of events. Dropped on close.
func (s *Subscription) Chan() <-chan ResourceEvent { return s.sub.ch }

// EventBus fans out ResourceEvents to any number of subscribers. Subscribers
// that fall behind drop events rather than blocking the publisher — this keeps
// a stuck WS client from stalling the informer workers.
type EventBus struct {
	mu     sync.RWMutex
	nextID int
	subs   map[int]*eventSubscriber
}

func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[int]*eventSubscriber)}
}

// Subscribe filters by namespace ("" = all namespaces, including cluster-scoped
// objects like Namespace itself).
func (b *EventBus) Subscribe(namespace string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	sub := &eventSubscriber{id: b.nextID, ns: namespace, ch: make(chan ResourceEvent, 256)}
	b.subs[sub.id] = sub
	return &Subscription{sub: sub, bus: b}
}

func (b *EventBus) Unsubscribe(s *Subscription) {
	if s == nil || s.sub == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[s.sub.id]; ok {
		delete(b.subs, s.sub.id)
		close(s.sub.ch)
	}
}

func (b *EventBus) Publish(ev ResourceEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if s.ns != "" && ev.Namespace != "" && s.ns != ev.Namespace {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// slow consumer; drop
		}
	}
}

// InformerCache holds SharedInformerFactory + listers for the resources the
// dashboard queries most often. Lifecycle (start/stop) is managed by Manager
// so credential swaps don't leak informer goroutines.
type InformerCache struct {
	factory informers.SharedInformerFactory
	stop    chan struct{}
	bus     *EventBus

	syncedMu sync.RWMutex
	synced   bool

	podLister        corelisters.PodLister
	deploymentLister appslisters.DeploymentLister
	serviceLister    corelisters.ServiceLister
	configmapLister  corelisters.ConfigMapLister
	ingressLister    networkinglisters.IngressLister
	cronjobLister    batchlisters.CronJobLister
	jobLister        batchlisters.JobLister
	namespaceLister  corelisters.NamespaceLister
}

func newInformerCache(client *kubernetes.Clientset, bus *EventBus) *InformerCache {
	// 10m resync keeps listers lively without flooding the API server; events
	// still arrive via the watch stream in near real-time.
	factory := informers.NewSharedInformerFactory(client, 10*time.Minute)
	ic := &InformerCache{
		factory: factory,
		stop:    make(chan struct{}),
		bus:     bus,
	}

	podInf := factory.Core().V1().Pods()
	ic.podLister = podInf.Lister()
	deployInf := factory.Apps().V1().Deployments()
	ic.deploymentLister = deployInf.Lister()
	svcInf := factory.Core().V1().Services()
	ic.serviceLister = svcInf.Lister()
	cmInf := factory.Core().V1().ConfigMaps()
	ic.configmapLister = cmInf.Lister()
	ingInf := factory.Networking().V1().Ingresses()
	ic.ingressLister = ingInf.Lister()
	cjInf := factory.Batch().V1().CronJobs()
	ic.cronjobLister = cjInf.Lister()
	jobInf := factory.Batch().V1().Jobs()
	ic.jobLister = jobInf.Lister()
	nsInf := factory.Core().V1().Namespaces()
	ic.namespaceLister = nsInf.Lister()
	evInf := factory.Core().V1().Events()

	attach := func(inf cache.SharedIndexInformer, kind string) {
		inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				if ev, ok := toResourceEvent("added", kind, obj); ok {
					ic.bus.Publish(ev)
				}
			},
			UpdateFunc: func(_, obj any) {
				if ev, ok := toResourceEvent("updated", kind, obj); ok {
					ic.bus.Publish(ev)
				}
			},
			DeleteFunc: func(obj any) {
				if ev, ok := toResourceEvent("deleted", kind, obj); ok {
					ic.bus.Publish(ev)
				}
			},
		})
	}
	attach(podInf.Informer(), "Pod")
	attach(deployInf.Informer(), "Deployment")
	attach(svcInf.Informer(), "Service")
	attach(cmInf.Informer(), "ConfigMap")
	attach(ingInf.Informer(), "Ingress")
	attach(cjInf.Informer(), "CronJob")
	attach(jobInf.Informer(), "Job")
	attach(nsInf.Informer(), "Namespace")

	// Native K8s Events — carry Reason/Message/Type that the UI shows verbatim.
	evInf.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			e, ok := obj.(*corev1.Event)
			if !ok {
				return
			}
			ic.bus.Publish(ResourceEvent{
				Verb:         "event",
				Kind:         "Event",
				Namespace:    e.Namespace,
				Name:         e.Name,
				At:           eventTime(e),
				Reason:       e.Reason,
				Message:      e.Message,
				Type:         e.Type,
				InvolvedKind: e.InvolvedObject.Kind,
				InvolvedName: e.InvolvedObject.Name,
			})
		},
	})

	return ic
}

func eventTime(e *corev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	if !e.FirstTimestamp.IsZero() {
		return e.FirstTimestamp.Time
	}
	return time.Now()
}

func toResourceEvent(verb, kind string, obj any) (ResourceEvent, bool) {
	accessor, ok := obj.(metav1.Object)
	if !ok {
		return ResourceEvent{}, false
	}
	return ResourceEvent{
		Verb:      verb,
		Kind:      kind,
		Namespace: accessor.GetNamespace(),
		Name:      accessor.GetName(),
		At:        time.Now(),
	}, true
}

func (c *InformerCache) start(ctx context.Context) {
	c.factory.Start(c.stop)
	// Bounded initial sync so a slow cluster doesn't delay readiness forever.
	syncCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c.factory.WaitForCacheSync(syncCtx.Done())
	c.syncedMu.Lock()
	c.synced = true
	c.syncedMu.Unlock()
}

func (c *InformerCache) stopAll() {
	select {
	case <-c.stop:
		// already stopped
	default:
		close(c.stop)
	}
	c.factory.Shutdown()
}

// Synced returns true once the initial list has populated every lister. Callers
// should fall back to a live API call when this is false, so the UI isn't
// forced to display an empty list during the warmup window.
func (c *InformerCache) Synced() bool {
	c.syncedMu.RLock()
	defer c.syncedMu.RUnlock()
	return c.synced
}
