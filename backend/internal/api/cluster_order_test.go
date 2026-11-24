package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"k8s-dashboard/backend/internal/models"
)

func clusterNames(t *testing.T, body string) []string {
	t.Helper()
	var out struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, c := range out.Items {
		names = append(names, c.Name)
	}
	return names
}

func TestClusterOrder(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, bob := e.user("bob", false)
	ctx := context.Background()
	gamma, err := e.store.CreateCluster(ctx, "gamma", "", models.KubeCredentials{Method: "token", Server: "https://example.invalid", Token: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	list := func() []string {
		return clusterNames(t, e.expect("GET", "/api/admin/clusters", admin, nil, http.StatusOK))
	}
	// A new cluster comes last; alpha (the default) first as it was created first.
	if got := list(); len(got) != 3 || got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("initial order = %v", got)
	}
	cs, _ := e.store.ListClusters(ctx)
	alpha, beta := cs[0].ID, cs[1].ID

	e.expect("PUT", "/api/admin/clusters/order", bob, map[string]any{"ids": []int{gamma, beta, alpha}}, http.StatusForbidden)
	e.waitAudit("cluster.update.denied", "admin_only")

	e.expect("PUT", "/api/admin/clusters/order", admin, map[string]any{"ids": []int{gamma, beta, alpha}}, http.StatusOK)
	e.waitAudit("cluster.update.success", "order")
	// The default cluster is not pulled to the top: the admin's order holds everywhere.
	if got := list(); got[0] != "gamma" || got[1] != "beta" || got[2] != "alpha" {
		t.Fatalf("saved order = %v", got)
	}
	if got := clusterNames(t, e.expect("GET", "/api/clusters/public", admin, nil, http.StatusOK)); got[0] != "gamma" || got[2] != "alpha" {
		t.Fatalf("switcher order = %v", got)
	}

	e.expect("PUT", "/api/admin/clusters/order", admin, map[string]any{"ids": []int{gamma, gamma, alpha}}, http.StatusBadRequest)
	e.expect("PUT", "/api/admin/clusters/order", admin, map[string]any{"ids": []int{gamma, 0, alpha}}, http.StatusBadRequest)
	// A cluster added or deleted meanwhile: the list no longer matches.
	e.expect("PUT", "/api/admin/clusters/order", admin, map[string]any{"ids": []int{gamma, beta}}, http.StatusConflict)
	e.expect("PUT", "/api/admin/clusters/order", admin, map[string]any{"ids": []int{gamma, beta, 999}}, http.StatusConflict)
	e.waitAudit("cluster.update.failed", "conflict")
	if got := list(); got[0] != "gamma" || got[1] != "beta" || got[2] != "alpha" {
		t.Fatalf("a refused order changed the list: %v", got)
	}
	// Added after a reorder: still last.
	if _, err := e.store.CreateCluster(ctx, "aaa", "", models.KubeCredentials{Method: "token", Server: "https://example.invalid", Token: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if got := list(); got[3] != "aaa" {
		t.Fatalf("new cluster not last: %v", got)
	}
}
