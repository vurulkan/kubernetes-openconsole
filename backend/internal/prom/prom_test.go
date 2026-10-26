package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

// fakeProm answers like Prometheus; answer picks the result per query.
func fakeProm(t *testing.T, check func(r *http.Request), answer func(path, query string) any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": answer(r.URL.Path, r.URL.Query().Get("query"))})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func vector(v string) any {
	return map[string]any{"resultType": "vector", "result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1.0, v}}}}
}

func TestSelectorAndRegex(t *testing.T) {
	c := &Client{cfg: models.PrometheusConfig{ClusterLabel: "k8s_cluster", ClusterValue: `pro"d`}}
	got := c.selector("shop", DeploymentRegex("web.v2", []string{"7d4f", "5c9a"}))
	want := `{namespace="shop",pod=~"web\\.v2-(7d4f|5c9a)-[a-z0-9]{5}",container!="",container!="POD",k8s_cluster="pro\"d"}`
	if got != want {
		t.Fatalf("selector\n got %s\nwant %s", got, want)
	}
	if _, err := New(models.PrometheusConfig{Mode: "url", URL: "http://x", ClusterLabel: `a"}or vector(1)`}, nil); err == nil {
		t.Fatal("a label name that is not a label name must be refused")
	}
}

func TestHistoryURLModeWithAuthAndHeaders(t *testing.T) {
	var queries []string
	srv := fakeProm(t, func(r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Scope-OrgID") != "team" {
			t.Errorf("headers = %v", r.Header)
		}
		if !strings.HasPrefix(r.URL.Path, "/prefix/api/v1/") {
			t.Errorf("path = %s (the URL's path prefix must be kept)", r.URL.Path)
		}
	}, func(path, q string) any {
		queries = append(queries, q)
		v := "0.25" // cores
		if strings.Contains(q, "memory") {
			v = "1048576"
		}
		return map[string]any{"resultType": "matrix", "result": []any{map[string]any{"values": []any{[]any{100.0, v}, []any{130.0, v}}}}}
	})
	c, err := New(models.PrometheusConfig{
		Mode: "url", URL: srv.URL + "/prefix", Auth: "bearer", Token: "tok",
		Headers: []models.Header{{Name: "X-Scope-OrgID", Value: "team"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pts, err := c.History(context.Background(), "shop", PodRegex("web-1"), "6h", time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 || pts[0].CPU != 250 || pts[0].Mem != 1<<20 {
		t.Fatalf("points = %+v", pts)
	}
	if !strings.Contains(queries[0], "[480s]") || !strings.Contains(queries[0], "max by (namespace, pod, container)") {
		t.Fatalf("cpu query = %s (6h step 2m → 8m window, max by against double scrapes)", queries[0])
	}
}

func TestDiagnose(t *testing.T) {
	answers := map[string]any{}
	srv := fakeProm(t, nil, func(path, q string) any {
		if strings.HasPrefix(path, "/api/v1/label/") {
			return answers["labels"]
		}
		for k, v := range answers {
			if strings.Contains(q, k) {
				return v
			}
		}
		return vector("1")
	})
	c, _ := New(models.PrometheusConfig{Mode: "url", URL: srv.URL}, nil)

	answers["labels"] = []string{"prod", "nonprod"}
	answers["> 1"] = vector("3")
	d := c.Diagnose(context.Background())
	if !d.OK || d.Steps[4].Reason != "multiple_clusters" || d.Steps[5].Reason != "duplicate_series" || len(d.ClusterValues) != 2 {
		t.Fatalf("multi-cluster, double scrape = %+v", d)
	}

	answers["count(container_memory_working_set_bytes"] = map[string]any{"resultType": "vector", "result": []any{}}
	if d := c.Diagnose(context.Background()); d.OK || d.Steps[len(d.Steps)-1].Reason != "no_container_metrics" {
		t.Fatalf("no cAdvisor = %+v", d)
	}

	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer deny.Close()
	c, _ = New(models.PrometheusConfig{Mode: "url", URL: deny.URL}, nil)
	if d := c.Diagnose(context.Background()); d.OK || d.Steps[0].ID != "auth" || d.Steps[0].Reason != "unauthorized" {
		t.Fatalf("401 = %+v", d)
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer html.Close()
	c, _ = New(models.PrometheusConfig{Mode: "url", URL: html.URL}, nil)
	if d := c.Diagnose(context.Background()); d.Steps[0].Reason != "not_prometheus" {
		t.Fatalf("html = %+v", d)
	}
}

// Azure Monitor managed Prometheus: a client-credentials token for the
// Prometheus scope, fetched once and reused.
func TestAzureToken(t *testing.T) {
	var tokenCalls atomic.Int32
	entra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.Form.Get("scope") != "https://prometheus.monitor.azure.com/.default" ||
			r.Form.Get("client_secret") != "s3cret" {
			t.Errorf("token request %s %v", r.URL.Path, r.Form)
		}
		tokenCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "aad-token", "expires_in": 3600})
	}))
	defer entra.Close()
	old := auth.AzureAuthority
	auth.AzureAuthority = entra.URL
	defer func() { auth.AzureAuthority = old }()

	srv := fakeProm(t, func(r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aad-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
	}, func(string, string) any { return vector("1") })
	c, _ := New(models.PrometheusConfig{Mode: "url", URL: srv.URL, Auth: "azure", AzureTenantID: "tenant-1", AzureClientID: "app", AzureClientSecret: "s3cret"}, nil)
	for i := 0; i < 3; i++ {
		if _, _, err := c.Query(context.Background(), "up"); err != nil {
			t.Fatal(err)
		}
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token fetched %d times, want 1", tokenCalls.Load())
	}
}
