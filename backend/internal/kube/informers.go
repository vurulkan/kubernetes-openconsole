package kube

import (
	"context"
	"sort"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	appslisters "k8s.io/client-go/listers/apps/v1"
	autoscalinglisters "k8s.io/client-go/listers/autoscaling/v2"
	batchlisters "k8s.io/client-go/listers/batch/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k8s-dashboard/backend/internal/models"
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

	podLister         corelisters.PodLister
	deploymentLister  appslisters.DeploymentLister
	daemonsetLister   appslisters.DaemonSetLister
	statefulsetLister appslisters.StatefulSetLister
	hpaLister         autoscalinglisters.HorizontalPodAutoscalerLister
	serviceLister     corelisters.ServiceLister
	configmapLister   corelisters.ConfigMapLister
	ingressLister     networkinglisters.IngressLister
	cronjobLister     batchlisters.CronJobLister
	jobLister         batchlisters.JobLister
	namespaceLister   corelisters.NamespaceLister
	eventLister       corelisters.EventLister
	podIndexer        cache.Indexer // also by spec.nodeName (podNodeIndex)
	// nodeLister is nil when the credentials may not list and watch nodes (set before the sync).
	nodeLister corelisters.NodeLister
	client     kubernetes.Interface

	countsMu sync.RWMutex
	counts   []CountPoint // every 5 min, the last 24 h
}

func newInformerCache(client kubernetes.Interface, bus *EventBus, onTermination func(models.ContainerTermination)) *InformerCache {
	// 10m resync keeps listers lively without flooding the API server; events
	// still arrive via the watch stream in near real-time.
	factory := informers.NewSharedInformerFactory(client, 10*time.Minute)
	ic := &InformerCache{
		factory: factory,
		stop:    make(chan struct{}),
		bus:     bus,
		client:  client,
	}

	podInf := factory.Core().V1().Pods()
	ic.podLister = podInf.Lister()
	_ = podInf.Informer().AddIndexers(cache.Indexers{podNodeIndex: func(obj any) ([]string, error) {
		if p, ok := obj.(*corev1.Pod); ok && p.Spec.NodeName != "" {
			return []string{p.Spec.NodeName}, nil
		}
		return nil, nil
	}})
	ic.podIndexer = podInf.Informer().GetIndexer()
	deployInf := factory.Apps().V1().Deployments()
	ic.deploymentLister = deployInf.Lister()
	dsInf := factory.Apps().V1().DaemonSets()
	ic.daemonsetLister = dsInf.Lister()
	ssInf := factory.Apps().V1().StatefulSets()
	ic.statefulsetLister = ssInf.Lister()
	hpaInf := factory.Autoscaling().V2().HorizontalPodAutoscalers()
	ic.hpaLister = hpaInf.Lister()
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
	ic.eventLister = evInf.Lister()

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
	if onTermination != nil {
		report := func(old, cur any) {
			p, ok := cur.(*corev1.Pod)
			if !ok || p.Status.Phase == "" {
				return
			}
			o, _ := old.(*corev1.Pod)
			for _, t := range podTerminations(o, p) {
				onTermination(t)
			}
		}
		podInf.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { report(nil, obj) },
			UpdateFunc: report,
		})
	}
	attach(deployInf.Informer(), "Deployment")
	attach(dsInf.Informer(), "DaemonSet")
	attach(ssInf.Informer(), "StatefulSet")
	attach(hpaInf.Informer(), "HorizontalPodAutoscaler")
	attach(svcInf.Informer(), "Service")
	attach(cmInf.Informer(), "ConfigMap")
	attach(ingInf.Informer(), "Ingress")
	attach(cjInf.Informer(), "CronJob")
	attach(jobInf.Informer(), "Job")
	attach(nsInf.Informer(), "Namespace")

	// Native K8s Events — carry Reason/Message/Type that the UI shows verbatim.
	// A repeating event (a failing probe) is one object whose count goes up: each
	// bump is published too, like `kubectl get events -w`; resyncs (same version) are not.
	publishEvent := func(obj any) {
		e, ok := obj.(*corev1.Event)
		if !ok {
			return
		}
		ic.bus.Publish(ResourceEvent{
			Verb:         "event",
			Kind:         "Event",
			Namespace:    e.Namespace,
			Name:         e.Name,
			At:           EventTime(e),
			Reason:       e.Reason,
			Message:      e.Message,
			Type:         e.Type,
			InvolvedKind: e.InvolvedObject.Kind,
			InvolvedName: e.InvolvedObject.Name,
		})
	}
	evInf.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: publishEvent,
		UpdateFunc: func(old, cur any) {
			if o, ok := old.(*corev1.Event); ok && o.ResourceVersion == cur.(*corev1.Event).ResourceVersion {
				return
			}
			publishEvent(cur)
		},
	})

	return ic
}

// EventTime is when an event last happened (Kubernetes fills one of three fields).
func EventTime(e *corev1.Event) time.Time {
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
	// Nodes only with list + watch: a token from an older rbac.yaml would otherwise hold up
	// the sync for 20 s and log a refused watch forever; the node screen then lists them itself.
	probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
	defer cancelProbe()
	if canWatchNodes(probeCtx, c.client) {
		c.nodeLister = c.factory.Core().V1().Nodes().Lister()
	}
	c.factory.Start(c.stop)
	// Bounded initial sync so a slow cluster doesn't delay readiness forever.
	syncCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c.factory.WaitForCacheSync(syncCtx.Done())
	c.syncedMu.Lock()
	c.synced = true
	c.syncedMu.Unlock()
	go c.sampleCounts()
}

// CountPoint is the cluster's pod and deployment health at one moment (overview sparklines).
type CountPoint struct {
	T             int64 `json:"t"`
	PodsRunning   int   `json:"podsRunning"`
	Pods          int   `json:"pods"`
	PodsAttention int   `json:"podsAttention"`
	DeploysReady  int   `json:"deploysReady"`
	Deploys       int   `json:"deploys"`
}

// PodNeedsAttention is true for a pod that the UI's status logic (frontend utils/podStatus.ts)
// may paint red or amber: anything but a running pod with every container ready, or a finished one.
// The UI classifies these candidates; this side only narrows 700 pods down to them.
func PodNeedsAttention(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil {
		return true
	}
	switch p.Status.Phase {
	case corev1.PodSucceeded:
		return false
	case corev1.PodRunning:
		for _, c := range p.Status.ContainerStatuses {
			if !c.Ready {
				return true
			}
		}
		return len(p.Status.ContainerStatuses) == 0
	}
	return true
}

// DeploymentReady: every desired replica is ready.
func DeploymentReady(d *appsv1.Deployment) bool {
	want := int32(1)
	if d.Spec.Replicas != nil {
		want = *d.Spec.Replicas
	}
	return d.Status.ReadyReplicas >= want
}

// CountsOf summarizes pods and deployments at time t.
func CountsOf(t int64, pods []*corev1.Pod, deploys []*appsv1.Deployment) CountPoint {
	cp := CountPoint{T: t, Pods: len(pods), Deploys: len(deploys)}
	for _, p := range pods {
		if p.Status.Phase == corev1.PodRunning {
			cp.PodsRunning++
		}
		if PodNeedsAttention(p) {
			cp.PodsAttention++
		}
	}
	for _, d := range deploys {
		if DeploymentReady(d) {
			cp.DeploysReady++
		}
	}
	return cp
}

func (c *InformerCache) sampleCounts() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		pods, _ := c.podLister.List(labels.Everything())
		deploys, _ := c.deploymentLister.List(labels.Everything())
		cp := CountsOf(time.Now().Unix(), pods, deploys)
		c.countsMu.Lock()
		c.counts = append(c.counts, cp)
		if len(c.counts) > 288 {
			c.counts = c.counts[len(c.counts)-288:]
		}
		c.countsMu.Unlock()
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
	}
}

// CountHistory is the last 24 h of CountsOf, every 5 minutes since the cache started.
func (c *InformerCache) CountHistory() []CountPoint {
	c.countsMu.RLock()
	defer c.countsMu.RUnlock()
	return append([]CountPoint(nil), c.counts...)
}

// WarningEvents lists Warning events seen since (newest first) from the cache.
func (c *InformerCache) WarningEvents(since time.Time) []corev1.Event {
	evs, _ := c.eventLister.List(labels.Everything())
	out := []corev1.Event{}
	for _, e := range evs {
		if e.Type == corev1.EventTypeWarning && !EventTime(e).Before(since) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return EventTime(&out[i]).After(EventTime(&out[j])) })
	return out
}

const podNodeIndex = "nodeName"

func canWatchNodes(ctx context.Context, client kubernetes.Interface) bool {
	for _, verb := range []string{"list", "watch"} {
		r, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: verb, Resource: "nodes"}},
		}, metav1.CreateOptions{})
		if err != nil || !r.Status.Allowed {
			return false
		}
	}
	return true
}

// Nodes lists the cluster's nodes from the cache; false when nodes aren't watched or the cache is cold.
func (c *InformerCache) Nodes() ([]*corev1.Node, bool) {
	if !c.Synced() || c.nodeLister == nil {
		return nil, false
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	return nodes, err == nil
}

// NodePods are the pods scheduled to a node (the nodeName index).
func (c *InformerCache) NodePods(node string) []*corev1.Pod {
	objs, _ := c.podIndexer.ByIndex(podNodeIndex, node)
	out := make([]*corev1.Pod, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.(*corev1.Pod))
	}
	return out
}

// PodNode is the node a pod runs on, "" when unknown (the sampler's node series).
func (c *InformerCache) PodNode(namespace, name string) string {
	if p, err := c.podLister.Pods(namespace).Get(name); err == nil {
		return p.Spec.NodeName
	}
	return ""
}

// NodeEvents lists the events about a node from the cache.
func (c *InformerCache) NodeEvents(node string) []corev1.Event {
	evs, _ := c.eventLister.List(labels.Everything())
	out := []corev1.Event{}
	for _, e := range evs {
		if e.InvolvedObject.Kind == "Node" && e.InvolvedObject.Name == node {
			out = append(out, *e)
		}
	}
	return out
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
