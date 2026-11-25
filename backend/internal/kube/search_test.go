package kube

import (
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func searchPodObj(ns, name, ip string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}}}
}

// allowNodes answers the node list / watch access review, so the cache watches nodes.
func allowNodes(c *fake.Clientset) {
	c.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
}

func TestSearch(t *testing.T) {
	client := fake.NewSimpleClientset(
		searchPodObj("prod", "web-1", "10.42.0.7"),
		searchPodObj("prod", "api-web", "10.42.0.70"),
		searchPodObj("secret-ns", "web-hidden", "10.42.0.8"),
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.43.0.10"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.42.0.7"}}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.43.0.11"},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "10.42.0.200"}}}}},
	)
	allowNodes(client)
	m, _ := startCache(t, client)
	ic := m.Informers()
	for _, k := range []string{"Pod", "Deployment", "Service", "Node"} {
		waitFor(t, k, func() bool { return ic.Usable(k) })
	}
	onlyProd := func(ns, _ string) bool { return ns == "prod" }
	names := func(hits []SearchHit) []string {
		out := []string{}
		for _, h := range hits {
			out = append(out, h.Kind+"/"+h.Name+"@"+h.IP)
		}
		return out
	}
	cases := []struct {
		q    SearchQuery
		want string
	}{
		// prefix before substring, kinds in order, the other namespace invisible
		{SearchQuery{Text: "web"}, "[pods/web-1@ deployments/web@ services/web@ pods/api-web@]"},
		{SearchQuery{Text: "web", Kind: "services"}, "[services/web@]"},
		{SearchQuery{Text: "web", Namespace: "pr"}, "[pods/web-1@ deployments/web@ services/web@ pods/api-web@]"},
		{SearchQuery{Text: "web", Namespace: "x"}, "[]"},
		{SearchQuery{Text: "node", Namespace: "pr", Nodes: true}, "[]"},
		{SearchQuery{Text: "node", Nodes: true}, "[nodes/node-a@]"},
		// IP: exact first, the node (admin) before its pods; no IP from a namespace without access
		{SearchQuery{Text: "10.42.0.7", Nodes: true}, "[nodes/node-a@10.42.0.7 pods/web-1@10.42.0.7 pods/api-web@10.42.0.70]"},
		{SearchQuery{Text: "10.42.0.8"}, "[]"},
		{SearchQuery{Text: "10.43."}, "[services/lb@10.43.0.11 services/web@10.43.0.10]"},
		// a prefix: the LoadBalancer Service before the node and the pods in the same range
		{SearchQuery{Text: "10.42.0.", Nodes: true, Limit: 2}, "[services/lb@10.42.0.200 nodes/node-a@10.42.0.7]"},
		// nodes only for admins; a bare number is a name search
		{SearchQuery{Text: "node"}, "[]"},
		{SearchQuery{Text: "10"}, "[]"},
		{SearchQuery{Text: "web", Limit: 2}, "[pods/web-1@ deployments/web@]"},
	}
	for _, c := range cases {
		if got := fmt.Sprint(names(ic.Search(c.q, onlyProd))); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.q, got, c.want)
		}
	}
	hits := ic.Search(SearchQuery{Text: "web-1"}, onlyProd)
	if len(hits) != 1 || hits[0].Pod == nil || hits[0].Pod.Status.Phase != corev1.PodRunning {
		t.Fatalf("a pod hit carries its status: %+v", hits)
	}
}

func TestLooksLikeIP(t *testing.T) {
	for q, want := range map[string]bool{"10.42.": true, "10.42.0.7": true, "10": false, "web.1": false, "": false} {
		if LooksLikeIP(q) != want {
			t.Errorf("LooksLikeIP(%q) = %v", q, !want)
		}
	}
}

// BenchmarkSearch: 10k pods in 200 namespaces (+ 2k Deployments, 2k Services),
// a user with access to every second namespace.
func BenchmarkSearch(b *testing.B) {
	var objs []runtime.Object
	for i := 0; i < 10000; i++ {
		ns := fmt.Sprintf("ns-%d", i%200)
		objs = append(objs, searchPodObj(ns, fmt.Sprintf("app-%d-7f9c-%d", i%500, i), fmt.Sprintf("10.42.%d.%d", i/250, i%250)))
		if i%5 == 0 {
			objs = append(objs, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("app-%d", i), Namespace: ns}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("app-%d", i), Namespace: ns}})
		}
	}
	m, _ := startCache(&testing.T{}, fake.NewSimpleClientset(objs...))
	ic := m.Informers()
	for !ic.Usable("Pod") || !ic.Usable("Deployment") || !ic.Usable("Service") {
		time.Sleep(10 * time.Millisecond)
	}
	allow := func(ns, _ string) bool { return ns[len(ns)-1]%2 == 0 }
	for _, q := range []string{"app-1", "zz", "10.42.3.", "pp"} {
		b.Run(q, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ic.Search(SearchQuery{Text: q, Limit: 30}, allow)
			}
		})
	}
}
