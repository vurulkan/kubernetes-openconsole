package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

func TestPrometheusSettingsAndHistory(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	var mu sync.Mutex // CPU and memory are asked at once
	var gotAuth, gotQuery string
	promSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.Query().Get("query")
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"values":[[100,"0.5"],[130,"0.5"]]}]}}`)
	}))
	defer promSrv.Close()
	base := fmt.Sprintf("/api/admin/clusters/%d/prometheus", e.alphaID)

	cfg := models.PrometheusConfig{Mode: "url", URL: promSrv.URL, Auth: "bearer", Token: "t0ken",
		Headers: []models.Header{{Name: "X-Scope-OrgID", Value: "tenant-a"}}}
	out := e.expect("PUT", base, admin, cfg, http.StatusOK)
	if strings.Contains(out, "t0ken") || strings.Contains(out, "tenant-a") {
		t.Fatalf("secrets returned: %s", out)
	}
	// The form sends the mask back: the stored token is kept.
	var masked models.PrometheusConfig
	_ = json.Unmarshal([]byte(e.expect("GET", base, admin, nil, http.StatusOK)), &masked)
	masked.ClusterLabel = "cluster"
	e.expect("PUT", base, admin, masked, http.StatusOK)
	if stored, _ := e.store.GetPrometheus(context.Background(), e.alphaID); stored.Token != "t0ken" || stored.Headers[0].Value != "tenant-a" {
		t.Fatalf("stored = %+v", stored)
	}
	e.waitAudit("cluster.update", `"changed":["prometheus"]`)

	bad := masked
	bad.ClusterLabel = `x"}`
	e.expect("PUT", base, admin, bad, http.StatusBadRequest)

	out = e.expect("GET", "/api/namespaces/team-a/metrics/pods/api-1?range=7d", admin, nil, http.StatusOK)
	var hist struct {
		Source string
		Ranges []string
		Points []struct{ CPU int64 }
	}
	_ = json.Unmarshal([]byte(out), &hist)
	if hist.Source != "prometheus" || len(hist.Ranges) != 4 || len(hist.Points) != 2 || hist.Points[0].CPU != 500 {
		t.Fatalf("history = %s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer t0ken" || !strings.Contains(gotQuery, `pod=~"api-1"`) || !strings.Contains(gotQuery, `namespace="team-a"`) {
		t.Fatalf("query %q auth %q", gotQuery, gotAuth)
	}

	// Prometheus down: the in-memory samples, and a note saying so.
	m := kube.NewMetricsSampler(func(context.Context) ([]kube.PodUsage, error) {
		return []kube.PodUsage{{Namespace: "team-a", Name: "api-1", Usage: kube.Usage{CPU: 7, Mem: 9}}}, nil
	})
	m.Sample(time.Now())
	e.alpha.UseMetrics(m)
	promSrv.Close()
	out = e.expect("GET", "/api/namespaces/team-a/metrics/pods/api-1?range=1h", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"source":"memory"`) || !strings.Contains(out, `"note":"prometheus_unreachable"`) || !strings.Contains(out, `"cpu":7`) {
		t.Fatalf("fallback = %s", out)
	}

	// Cleared: back to memory without a note.
	e.expect("PUT", base, admin, models.PrometheusConfig{}, http.StatusOK)
	if out = e.expect("GET", "/api/namespaces/team-a/metrics/pods/api-1", admin, nil, http.StatusOK); strings.Contains(out, "note") {
		t.Fatalf("after clearing = %s", out)
	}

	_, nobody := e.user("nobody", false)
	e.expect("GET", base, nobody, nil, http.StatusForbidden)
}
