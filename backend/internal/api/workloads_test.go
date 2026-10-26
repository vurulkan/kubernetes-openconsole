package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// A Deployment's revisions are its own ReplicaSets, newest first; a ReplicaSet
// that matches the labels but belongs to another Deployment is left out.
func TestDeploymentReplicaSets(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	ctx := context.Background()
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	web := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", UID: types.UID("web-uid")}, Spec: appsv1.DeploymentSpec{Selector: sel}}
	if _, err := e.client.AppsV1().Deployments("team-a").Create(ctx, web, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	yes := true
	rs := func(name, rev, owner, image string) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: "team-a",
				Labels:          map[string]string{"app": "web", "pod-template-hash": name[len(name)-3:]},
				Annotations:     map[string]string{"deployment.kubernetes.io/revision": rev},
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "x", UID: types.UID(owner), Controller: &yes}},
			},
			Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}}},
		}
	}
	for _, r := range []*appsv1.ReplicaSet{
		rs("web-aaa", "9", "web-uid", "web:1.9"),
		rs("web-bbb", "10", "web-uid", "web:1.10"),
		rs("other-ccc", "11", "other-uid", "other:1"),
	} {
		if _, err := e.client.AppsV1().ReplicaSets("team-a").Create(ctx, r, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	out := e.expect("GET", "/api/namespaces/team-a/deployments/web/replicasets", admin, nil, http.StatusOK)
	var got struct{ Items []replicaSetRevision }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 || got.Items[0].Revision != "10" || got.Items[1].Revision != "9" ||
		got.Items[0].Images[0] != "web:1.10" || got.Items[0].Hash != "bbb" {
		t.Fatalf("revisions = %+v", got.Items)
	}

	_, nobody := e.user("nobody", false)
	e.expect("GET", "/api/namespaces/team-a/deployments/web/replicasets", nobody, nil, http.StatusForbidden)
}

// Usage comes from the cluster's sampler, scoped to the namespace and
// guarded like the pod list.
func TestPodMetricsEndpoints(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	m := kube.NewMetricsSampler(func(context.Context) ([]kube.PodUsage, error) {
		return []kube.PodUsage{
			{Namespace: "team-a", Name: "api-7d-x1", Owner: "Deployment/api", Usage: kube.Usage{CPU: 120, Mem: 64 << 20}, Containers: map[string]kube.Usage{"app": {CPU: 120, Mem: 64 << 20}}},
			{Namespace: "team-b", Name: "secret-pod", Usage: kube.Usage{CPU: 1, Mem: 1}},
		}, nil
	})
	e.alpha.UseMetrics(m)

	out := e.expect("GET", "/api/namespaces/team-a/metrics/pods", admin, nil, http.StatusOK)
	var snap kube.Snapshot
	_ = json.Unmarshal([]byte(out), &snap)
	if snap.Available || snap.Reason != "warming_up" {
		t.Fatalf("before sampling = %+v", snap)
	}
	m.Sample(time.Now())
	out = e.expect("GET", "/api/namespaces/team-a/metrics/pods", admin, nil, http.StatusOK)
	_ = json.Unmarshal([]byte(out), &snap)
	if !snap.Available || len(snap.Items) != 1 || snap.Items[0].Name != "api-7d-x1" || snap.Items[0].CPU != 120 {
		t.Fatalf("snapshot = %+v", snap)
	}
	out = e.expect("GET", "/api/namespaces/team-a/metrics/deployments/api?range=6h", admin, nil, http.StatusOK)
	var hist struct {
		Source string
		Points []kube.Point
	}
	_ = json.Unmarshal([]byte(out), &hist)
	if hist.Source != "memory" || len(hist.Points) != 1 || hist.Points[0].Mem != 64<<20 {
		t.Fatalf("deployment history = %+v", hist)
	}

	_, nobody := e.user("nobody", false)
	e.expect("GET", "/api/namespaces/team-a/metrics/pods", nobody, nil, http.StatusForbidden)
	e.expect("GET", "/api/namespaces/team-a/metrics/pods/api-7d-x1", nobody, nil, http.StatusForbidden)
}

// Restart history is read per deployment or pod, for the request's cluster only.
func TestRestartHistoryEndpoints(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	now := time.Now().UTC().Truncate(time.Second)
	for cluster, reason := range map[int]string{e.alphaID: "OOMKilled", e.alphaID + 1000: "Error"} {
		if err := e.store.RecordTermination(context.Background(), cluster, models.ContainerTermination{
			Namespace: "team-a", Pod: "api-7d-x1", Container: "app", Owner: "Deployment/api", ExitCode: 137, Reason: reason, FirstAt: now, LastAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/namespaces/team-a/deployments/api/restarts", "/api/namespaces/team-a/pods/api-7d-x1/restarts?days=7"} {
		out := e.expect("GET", path, admin, nil, http.StatusOK)
		var got struct{ Items []models.ContainerTermination }
		_ = json.Unmarshal([]byte(out), &got)
		if len(got.Items) != 1 || got.Items[0].Reason != "OOMKilled" || got.Items[0].Count != 1 {
			t.Fatalf("%s = %s", path, out)
		}
	}
	_, nobody := e.user("nobody", false)
	e.expect("GET", "/api/namespaces/team-a/deployments/api/restarts", nobody, nil, http.StatusForbidden)
}
