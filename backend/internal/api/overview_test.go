package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

func TestExitsIn(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 11 exits, one every 6 minutes from 00:00 to 01:00.
	loop := models.ContainerTermination{Count: 11, FirstAt: base, LastAt: base.Add(time.Hour)}
	for _, tc := range []struct {
		from, to time.Duration
		want     int
	}{
		{0, time.Hour, 10},                      // 00:00 … 00:54; 01:00 belongs to the next hour
		{time.Hour, 2 * time.Hour, 1},           // 01:00
		{-time.Hour, 0, 0},                      // before the first
		{30 * time.Minute, 31 * time.Minute, 1}, // 00:30
	} {
		if got := exitsIn(loop, base.Add(tc.from), base.Add(tc.to)); got != tc.want {
			t.Errorf("[%v, %v): %d, want %d", tc.from, tc.to, got, tc.want)
		}
	}
	single := models.ContainerTermination{Count: 1, FirstAt: base, LastAt: base}
	if exitsIn(single, base, base.Add(time.Minute)) != 1 || exitsIn(single, base.Add(time.Second), base.Add(time.Minute)) != 0 {
		t.Error("single exit")
	}
}

func TestRestartSummary(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)
	rows := []models.ContainerTermination{
		{Namespace: "a", Owner: "Deployment/web", ExitCode: 137, Reason: "OOMKilled", Count: 3, FirstAt: now.Add(-2 * time.Hour), LastAt: now.Add(-time.Hour)},
		{Namespace: "a", Owner: "Deployment/web", ExitCode: 1, Count: 1, FirstAt: now.Add(-10 * time.Minute), LastAt: now.Add(-10 * time.Minute)},
		{Namespace: "b", Pod: "lonely", ExitCode: 2, Count: 1, FirstAt: now.Add(-30 * time.Hour), LastAt: now.Add(-30 * time.Hour)}, // too old
	}
	start, hourly, total, top := restartSummary(rows, now)
	if time.Unix(start, 0).UTC() != time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC) || len(hourly) != 24 {
		t.Fatalf("start %v, %d buckets", time.Unix(start, 0).UTC(), len(hourly))
	}
	if total != 4 || hourly[23] != 1 {
		t.Fatalf("total %d, hourly %v", total, hourly)
	}
	if len(top) != 1 || top[0].Owner != "Deployment/web" || top[0].Restarts != 4 || top[0].ExitCode != 137 || top[0].Share != 3 || top[0].Reason != "OOMKilled" {
		t.Fatalf("top = %+v", top)
	}
}

func TestOverview(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, bob := e.user("bob", false)
	e.expect("GET", "/api/admin/overview", bob, nil, http.StatusForbidden)
	e.waitAudit("cluster.view_overview.denied", "")

	ctx := context.Background()
	mem := resource.MustParse("100Mi")
	for _, obj := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "team-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true}}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: mem}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "crash", Namespace: "team-a", Labels: map[string]string{"secret-label": "x"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "team-b"}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
	} {
		if _, err := e.client.CoreV1().Pods(obj.Namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{
		Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi")},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue}},
	}}
	if _, err := e.client.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	fetchNodeUsage = func(context.Context, kubernetes.Interface) (map[string]kube.Usage, error) {
		return map[string]kube.Usage{"n1": {CPU: 500, Mem: 1 << 30}}, nil
	}
	sampler := kube.NewMetricsSampler(func(context.Context) ([]kube.PodUsage, error) {
		return []kube.PodUsage{{Namespace: "team-a", Name: "ok", Usage: kube.Usage{CPU: 200, Mem: 95 << 20},
			Containers: map[string]kube.Usage{"app": {CPU: 200, Mem: 95 << 20}}}}, nil
	})
	sampler.Sample(time.Now())
	e.alpha.UseMetrics(sampler)

	var got overviewResponse
	body := e.expect("GET", "/api/admin/overview", admin, nil, http.StatusOK)
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	e.waitAudit("cluster.view_overview.success", "alpha")
	if got.Cluster.Name != "alpha" || got.Cluster.Nodes != 1 || got.Pods.Total != 5 || got.Pods.Running != 2 {
		t.Fatalf("cluster %+v pods %+v", got.Cluster, got.Pods)
	}
	// api-1 ×2 (no status) and crash need attention; ok and done don't. Labels other than the hash are dropped.
	if got.AttentionTotal != 3 || len(got.Attention) != 3 || got.Attention[1].Name != "crash" || len(got.Attention[1].Labels) != 0 {
		t.Fatalf("attention %d %+v", got.AttentionTotal, got.Attention)
	}
	n := got.Nodes[0]
	if !n.Ready || len(n.Pressure) != 1 || n.Pressure[0] != "MemoryPressure" || *n.CPU != 500 || n.CPUAllocatable != 2000 {
		t.Fatalf("node %+v", n)
	}
	if got.MetricsSource != "memory" || got.Usage == nil || got.Usage.CPU != 200 || got.Usage.CPUAllocatable != 2000 {
		t.Fatalf("usage %s %+v", got.MetricsSource, got.Usage)
	}
	if len(got.Namespaces) != 1 || got.Namespaces[0].Name != "team-a" || got.Namespaces[0].NearLimit != 1 {
		t.Fatalf("namespaces %+v", got.Namespaces)
	}

	// The 24 h history comes on its own; without Prometheus, from the sampler.
	e.expect("GET", "/api/admin/overview/history", bob, nil, http.StatusForbidden)
	var hist struct {
		Source string       `json:"source"`
		Points []kube.Point `json:"points"`
	}
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/overview/history", admin, nil, http.StatusOK)), &hist)
	if hist.Source != "memory" || len(hist.Points) != 1 || hist.Points[0].CPU != 200 {
		t.Fatalf("history %+v", hist)
	}

	// Cached for 15 s: the same answer, even after the cluster changed.
	_ = e.client.CoreV1().Pods("team-a").Delete(ctx, "crash", metav1.DeleteOptions{})
	var again overviewResponse
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/overview", admin, nil, http.StatusOK)), &again)
	if !again.GeneratedAt.Equal(got.GeneratedAt) || again.AttentionTotal != 3 {
		t.Fatalf("not served from cache: %v vs %v", again.GeneratedAt, got.GeneratedAt)
	}
}
