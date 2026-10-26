package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestParsePodMetrics(t *testing.T) {
	raw := []byte(`{"items":[{"metadata":{"name":"web-7d4f9-abcde","namespace":"shop","labels":{"pod-template-hash":"7d4f9"}},
		"containers":[{"name":"app","usage":{"cpu":"250m","memory":"64Mi"}},{"name":"sidecar","usage":{"cpu":"1500000n","memory":"1048576"}}]},
		{"metadata":{"name":"db-0","namespace":"shop","labels":{"statefulset.kubernetes.io/pod-name":"db-0"}},"containers":[{"name":"pg","usage":{"cpu":"1","memory":"1Gi"}}]},
		{"metadata":{"name":"agent-x7k2p","namespace":"shop","labels":{"pod-template-generation":"3","controller-revision-hash":"6d9f"}},"containers":[]},
		{"metadata":{"name":"bare","namespace":"shop","labels":{}},"containers":[]}]}`)
	pods, err := parsePodMetrics(raw)
	if err != nil {
		t.Fatal(err)
	}
	web := pods[0]
	if web.Owner != "Deployment/web" || web.CPU != 252 || web.Mem != 65*1024*1024 || web.Containers["app"].CPU != 250 {
		t.Fatalf("web = %+v", web)
	}
	if db := pods[1]; db.Owner != "StatefulSet/db" || db.CPU != 1000 || db.Mem != 1<<30 {
		t.Fatalf("db = %+v", db)
	}
	if pods[2].Owner != "DaemonSet/agent" || pods[3].Owner != "" {
		t.Fatalf("daemonset / bare = %q / %q", pods[2].Owner, pods[3].Owner)
	}
}

func TestSamplerHistory(t *testing.T) {
	cpu := int64(100)
	pods := func() []PodUsage {
		return []PodUsage{
			{Namespace: "shop", Name: "web-h-1", Owner: "Deployment/web", Usage: Usage{CPU: cpu, Mem: 10}},
			{Namespace: "shop", Name: "web-h-2", Owner: "Deployment/web", Usage: Usage{CPU: cpu, Mem: 20}},
			{Namespace: "other", Name: "web-h-3", Owner: "Deployment/web", Usage: Usage{CPU: 999, Mem: 999}},
		}
	}
	m := NewMetricsSampler(func(context.Context) ([]PodUsage, error) { return pods(), nil })
	m.nodeOf = func(ns, pod string) string {
		if ns == "shop" {
			return "node-a"
		}
		return "" // not in the cache (yet): counts for no node
	}
	start := time.Unix(1_800_000_000, 0) // a 5-minute boundary
	// 3 hours of samples every 30 s; CPU steps up by 1 every sample.
	var now time.Time
	for i := 0; i < 3*120; i++ {
		now = start.Add(time.Duration(i) * sampleInterval)
		cpu = int64(100 + i)
		m.Sample(now)
	}

	fine := m.PodHistory("shop", "web-h-1", 30*time.Minute, now)
	if len(fine) != 61 || fine[len(fine)-1].CPU != cpu {
		t.Fatalf("30 min = %d points, last %+v", len(fine), fine[len(fine)-1])
	}
	day := m.PodHistory("shop", "web-h-1", 24*time.Hour, now)
	// 2 h of 5-minute averages before the fine window, then 1 h of 30 s samples.
	if len(day) != 24+121 {
		t.Fatalf("24 h = %d points", len(day))
	}
	if first := day[0]; first.T != start.Unix() || first.CPU != 100+4 { // average of samples 0..9
		t.Fatalf("first average = %+v", first)
	}
	dep := m.OwnerHistory("shop", "Deployment/web", time.Hour, now)
	if last := dep[len(dep)-1]; last.CPU != 2*cpu || last.Mem != 30 {
		t.Fatalf("deployment sum = %+v (other namespaces must not count)", last)
	}

	if node := m.NodeHistory("node-a", time.Hour, now); len(node) != 121 || node[len(node)-1].CPU != 2*cpu {
		t.Fatalf("node sum = %d points, last %+v", len(node), node[len(node)-1])
	}

	snap := m.Namespace("shop")
	if !snap.Available || len(snap.Items) != 2 || snap.Items[0].Name != "web-h-1" {
		t.Fatalf("snapshot = %+v", snap)
	}

	// A pod gone for more than 24 h is forgotten.
	pods = func() []PodUsage { return nil }
	m.Sample(now.Add(historyWindow + time.Minute))
	if h := m.PodHistory("shop", "web-h-1", 24*time.Hour, now); len(h) != 0 {
		t.Fatalf("stale series kept: %d points", len(h))
	}
	if h := m.NodeHistory("node-a", 24*time.Hour, now); len(h) != 0 {
		t.Fatalf("stale node series kept: %d points", len(h))
	}
}

func TestSamplerUnavailable(t *testing.T) {
	m := NewMetricsSampler(func(context.Context) ([]PodUsage, error) { return nil, nil })
	if snap := m.Namespace("x"); snap.Available || snap.Reason != "warming_up" {
		t.Fatalf("before the first sample = %+v", snap)
	}
	for err, want := range map[error]string{
		apierrors.NewNotFound(schema.GroupResource{Group: "metrics.k8s.io", Resource: "pods"}, ""):                    "metrics_server_missing",
		apierrors.NewServiceUnavailable("no endpoints"):                                                               "metrics_server_missing",
		apierrors.NewForbidden(schema.GroupResource{Group: "metrics.k8s.io", Resource: "pods"}, "", errors.New("no")): "forbidden",
		errors.New("dial tcp: timeout"):                                                                               "error",
	} {
		m.fetch = func(context.Context) ([]PodUsage, error) { return nil, err }
		m.Sample(time.Now())
		if snap := m.Namespace("x"); snap.Available || snap.Reason != want {
			t.Fatalf("%v → %+v, want %s", err, snap, want)
		}
	}
}
