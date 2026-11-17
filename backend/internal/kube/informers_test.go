package kube

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// startCache runs a real informer cache on a fake clientset, the way
// ApplyCredentials does, and returns a request context carrying its Manager.
func startCache(t *testing.T, client *fake.Clientset) (*Manager, context.Context) {
	t.Helper()
	ic := newInformerCache(client, NewEventBus(), nil)
	go ic.start(context.Background())
	t.Cleanup(ic.stopAll)
	m := &Manager{bus: NewEventBus(), client: client, ready: true, informers: ic}
	return m, WithManager(context.Background(), m)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A kind the credentials may not list never syncs: its reads go to the API
// server and return the real 403, while the other kinds come from the cache.
// (Before M27 the whole cache counted as synced after 20 s and such a tab was
// an empty list for good.) The cluster still counts as connected.
func TestForbiddenKindReadsFromAPI(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "app"}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}},
	)
	client.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "", errors.New("no rule"))
	})
	m, ctx := startCache(t, client)
	waitFor(t, "pods in the cache", func() bool { return m.Informers().Usable("Pod") })

	rc := NewResourceClient()
	pods, err := rc.ListPods(ctx, "app")
	if err != nil || len(pods) != 1 {
		t.Fatalf("pods = %v, %v", pods, err)
	}
	if m.Informers().Usable("Ingress") {
		t.Fatal("a kind that never listed must not serve reads")
	}
	if items, err := rc.ListIngresses(ctx, "app"); !apierrors.IsForbidden(err) {
		t.Fatalf("ingresses = %v, %v; want the API server's 403", items, err)
	}
	if !m.Connected() {
		t.Fatal("a missing permission for one kind must not mark the cluster disconnected")
	}
}

// Credentials the cluster refuses: nothing syncs, the cluster is not
// connected (openconsole_cluster_connected 0), and reads return the error.
func TestRefusedCredentialsAreNotConnected(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "app"}})
	var listed atomic.Int32
	client.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		listed.Add(1)
		return true, nil, apierrors.NewUnauthorized("token revoked")
	})
	m, ctx := startCache(t, client)
	waitFor(t, "the informers to try", func() bool { return listed.Load() > 5 })
	if m.Connected() {
		t.Fatal("refused credentials reported as connected")
	}
	if _, err := NewResourceClient().ListPods(ctx, "app"); !apierrors.IsUnauthorized(err) {
		t.Fatalf("ListPods err = %v, want the API server's 401", err)
	}
}

// stubInformer is an informer whose sync state and resource version a test sets.
type stubInformer struct {
	cache.SharedIndexInformer
	synced bool
	rv     string
}

func (s *stubInformer) HasSynced() bool                 { return s.synced }
func (s *stubInformer) LastSyncResourceVersion() string { return s.rv }

// A failing watch takes a synced kind out of service until the informer
// makes progress again; a watch that merely expired doesn't.
func TestKindStateErrors(t *testing.T) {
	inf := &stubInformer{synced: true, rv: "10"}
	k := &kindState{inf: inf}
	if !k.usable() {
		t.Fatal("synced kind not usable")
	}
	k.failed(apierrors.NewResourceExpired("too old"))
	if !k.usable() {
		t.Fatal("an expired watch is routine")
	}
	k.failed(apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rule removed")))
	if k.usable() {
		t.Fatal("a failing kind must not serve stale reads")
	}
	inf.rv = "11" // listed again
	if !k.usable() {
		t.Fatal("progress after the error clears it")
	}
}

// Stopping a Manager (cluster edited or deleted) ends the Live Events
// subscriptions instead of leaving them open on a bus nothing feeds.
func TestStopClosesEventSubscriptions(t *testing.T) {
	m := NewManagerWithClient(fake.NewSimpleClientset())
	sub := m.EventBus().Subscribe("")
	m.Stop()
	select {
	case _, ok := <-sub.Chan():
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(time.Second):
		t.Fatal("subscription still open after Stop")
	}
	m.EventBus().Unsubscribe(sub) // the socket's deferred Unsubscribe must not panic
}

// The event frames carry how often an event happened, so the drawers update a
// row ("×5") instead of adding one per repeat (2.23.4).
func TestEventCount(t *testing.T) {
	for _, tc := range []struct {
		e    corev1.Event
		want int32
	}{
		{corev1.Event{}, 1},
		{corev1.Event{Count: 5}, 5},
		{corev1.Event{Count: 1, Series: &corev1.EventSeries{Count: 7}}, 7},
	} {
		if got := eventCount(&tc.e); got != tc.want {
			t.Errorf("%+v: %d, want %d", tc.e, got, tc.want)
		}
	}
	b, _ := json.Marshal(ResourceEvent{Verb: "event", Count: 3})
	if !strings.Contains(string(b), `"count":3`) {
		t.Fatalf("frame %s", b)
	}
}
