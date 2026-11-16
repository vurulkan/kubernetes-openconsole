package kube

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k8s-dashboard/backend/internal/models"
)

// cachedKind is one informer-backed list of ResourceClient, reduced to names.
type cachedKind struct {
	kind string
	list func(ctx context.Context, rc *ResourceClient) ([]string, error)
}

func names[T any](items []T, err error, name func(*T) string) ([]string, error) {
	out := make([]string, 0, len(items))
	for i := range items {
		out = append(out, name(&items[i]))
	}
	return out, err
}

var cachedKinds = []cachedKind{
	{"Namespace", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListNamespaces(ctx)
		return names(items, err, func(o *corev1.Namespace) string { return o.Name })
	}},
	{"Pod", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListPods(ctx, "app")
		return names(items, err, func(o *corev1.Pod) string { return o.Name })
	}},
	{"Deployment", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListDeployments(ctx, "app")
		return names(items, err, func(o *appsv1.Deployment) string { return o.Name })
	}},
	{"Service", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListServices(ctx, "app")
		return names(items, err, func(o *corev1.Service) string { return o.Name })
	}},
	{"ConfigMap", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListConfigMaps(ctx, "app")
		return names(items, err, func(o *corev1.ConfigMap) string { return o.Name })
	}},
	{"Ingress", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListIngresses(ctx, "app")
		return names(items, err, func(o *networkingv1.Ingress) string { return o.Name })
	}},
	{"CronJob", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListCronJobs(ctx, "app")
		return names(items, err, func(o *batchv1.CronJob) string { return o.Name })
	}},
	{"Job", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListJobs(ctx, "app")
		return names(items, err, func(o *batchv1.Job) string { return o.Name })
	}},
	{"DaemonSet", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListDaemonSets(ctx, "app")
		return names(items, err, func(o *appsv1.DaemonSet) string { return o.Name })
	}},
	{"StatefulSet", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListStatefulSets(ctx, "app")
		return names(items, err, func(o *appsv1.StatefulSet) string { return o.Name })
	}},
	{"HorizontalPodAutoscaler", func(ctx context.Context, rc *ResourceClient) ([]string, error) {
		items, err := rc.ListHPAs(ctx, "app")
		return names(items, err, func(o *autoscalingv2.HorizontalPodAutoscaler) string { return o.Name })
	}},
}

// twoOfEach seeds "b" before "a" of every cached kind, so a read also shows
// it sorts by name.
func twoOfEach() []runtime.Object {
	var objs []runtime.Object
	for _, n := range []string{"b", "a"} {
		meta := metav1.ObjectMeta{Name: n, Namespace: "app"}
		objs = append(objs,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}},
			&corev1.Pod{ObjectMeta: meta},
			&appsv1.Deployment{ObjectMeta: meta},
			&corev1.Service{ObjectMeta: meta},
			&corev1.ConfigMap{ObjectMeta: meta},
			&networkingv1.Ingress{ObjectMeta: meta},
			&batchv1.CronJob{ObjectMeta: meta},
			&batchv1.Job{ObjectMeta: meta},
			&appsv1.DaemonSet{ObjectMeta: meta},
			&appsv1.StatefulSet{ObjectMeta: meta},
			&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: meta},
		)
	}
	return objs
}

// Every informer-backed list: the API server while the cache warms up, the
// lister once the kind is usable (the API isn't asked), and the API server
// again, with its real error, once the kind's watch fails.
func TestListersServeOnlyWhileUsable(t *testing.T) {
	client := fake.NewSimpleClientset(twoOfEach()...)
	// Installed before any informer runs: PrependReactor isn't safe next to them.
	apiDownErr := errors.New("api server down")
	var apiDown atomic.Bool
	var apiLists atomic.Int32
	client.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		if !apiDown.Load() {
			return false, nil, nil
		}
		apiLists.Add(1)
		return true, nil, apiDownErr
	})
	ic := newInformerCache(client, NewEventBus(), nil)
	t.Cleanup(ic.stopAll)
	m := &Manager{bus: NewEventBus(), client: client, ready: true, informers: ic}
	ctx := WithManager(context.Background(), m)
	rc := NewResourceClient()

	// Warming up: not started, nothing synced.
	for _, k := range cachedKinds {
		if ic.Usable(k.kind) {
			t.Fatalf("%s usable before the cache started", k.kind)
		}
		got, err := k.list(ctx, rc)
		if err != nil || len(got) != 2 {
			t.Fatalf("%s while warming up = %v, %v; want the API server's list", k.kind, got, err)
		}
	}

	go ic.start(context.Background())
	for _, k := range cachedKinds {
		waitFor(t, k.kind+" usable", func() bool { return ic.Usable(k.kind) })
	}
	apiDown.Store(true)
	for _, k := range cachedKinds {
		got, err := k.list(ctx, rc)
		if err != nil || strings.Join(got, ",") != "a,b" {
			t.Fatalf("%s from the cache = %v, %v; want a,b", k.kind, got, err)
		}
	}
	if n := apiLists.Load(); n != 0 {
		t.Fatalf("%d list calls reached the API server while every kind was usable", n)
	}

	// A watch error the informer hasn't recovered from: back to the API server.
	for _, k := range cachedKinds {
		ic.kind(k.kind).failed(apierrors.NewForbidden(schema.GroupResource{Resource: k.kind}, "", errors.New("rule removed")))
		if ic.Usable(k.kind) {
			t.Fatalf("%s still usable after its watch failed", k.kind)
		}
		if got, err := k.list(ctx, rc); !errors.Is(err, apiDownErr) {
			t.Fatalf("%s after a failed watch = %v, %v; want the API server's error", k.kind, got, err)
		}
	}
}

// No cluster on the request, or a Manager without a client: ErrNotReady,
// never an empty list.
func TestListsWithoutClusterAreNotReady(t *testing.T) {
	rc := NewResourceClient()
	stopped := NewManagerWithClient(fake.NewSimpleClientset(twoOfEach()...))
	stopped.Stop()
	for _, ctx := range []context.Context{context.Background(), WithManager(context.Background(), stopped)} {
		for _, k := range cachedKinds {
			if got, err := k.list(ctx, rc); !errors.Is(err, ErrNotReady) {
				t.Fatalf("%s = %v, %v; want ErrNotReady", k.kind, got, err)
			}
		}
	}
	if ForContext(context.Background()) != noCluster {
		t.Fatal("ForContext without a cluster must be the empty Manager")
	}
}

// forbiddenAPI is an API server that refuses everything (enough to connect:
// connecting asks the cluster nothing).
func forbiddenAPI(t *testing.T) string {
	t.Helper()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
	}))
	t.Cleanup(hs.Close)
	return hs.URL
}

func TestRegistryGet(t *testing.T) {
	ctx := context.Background()
	if _, err := NewRegistry(nil).Get(ctx, 0); err == nil {
		t.Fatal("cluster 0 must be refused")
	}
	if _, err := NewRegistry(nil).Get(ctx, 1); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("no loader: %v", err)
	}
	gone := errors.New("no such cluster")
	if _, err := NewRegistry(func(context.Context, int) (models.KubeCredentials, error) {
		return models.KubeCredentials{}, gone
	}).Get(ctx, 3); !errors.Is(err, gone) {
		t.Fatalf("loader error not passed on: %v", err)
	}

	server := forbiddenAPI(t)
	var loads atomic.Int32
	creds := map[int]models.KubeCredentials{
		1: {Method: "token", Server: server, Token: []byte("x")},
		2: {Method: "kubeconfig", Kubeconfig: []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "` + server + `"}}]
users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1, command: /bin/true}}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
`)},
		4: {Method: "token"}, // no server: ApplyCredentials refuses
	}
	r := NewRegistry(func(_ context.Context, id int) (models.KubeCredentials, error) {
		loads.Add(1)
		return creds[id], nil
	})
	var terminated atomic.Int32
	r.OnTermination(func(id int, _ models.ContainerTermination) { terminated.Store(int32(id)) })

	m, err := r.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Invalidate(1) })
	if again, _ := r.Get(ctx, 1); again != m || loads.Load() != 1 {
		t.Fatalf("second Get connected again (loads %d)", loads.Load())
	}
	if m.Informers() == nil {
		t.Fatal("a connected cluster has an informer cache")
	}
	m.onTermination(models.ContainerTermination{})
	if terminated.Load() != 1 {
		t.Fatal("container exits are not reported with the cluster id")
	}
	if ids := r.Connected(); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("Connected = %v", ids)
	}
	if r.Ready(9) {
		t.Fatal("Ready of an unknown cluster")
	}

	// A kubeconfig that runs a program is refused, every time, and not kept.
	for i := 0; i < 2; i++ {
		if _, err := r.Get(ctx, 2); !errors.Is(err, ErrKubeconfigUnsupported) {
			t.Fatalf("exec kubeconfig: %v", err)
		}
	}
	if !r.warned[2] {
		t.Fatal("unsupported kubeconfig not remembered as logged")
	}
	if _, err := r.Get(ctx, 4); err == nil {
		t.Fatal("token credentials without a server connected")
	}
	if len(r.Connected()) != 1 {
		t.Fatalf("failed connections kept: %v", r.Connected())
	}

	// Invalidate: the Manager stops and the next Get connects anew.
	r.Invalidate(1)
	if _, ok := m.Client(); ok {
		t.Fatal("invalidated Manager still has a client")
	}
	m2, err := r.Get(ctx, 1)
	if err != nil || m2 == m {
		t.Fatalf("reconnect = %p, %v", m2, err)
	}

	// Put replaces and stops the previous Manager.
	r.Put(1, NewManagerWithClient(fake.NewSimpleClientset()))
	if _, ok := m2.Client(); ok {
		t.Fatal("replaced Manager still has a client")
	}
}
