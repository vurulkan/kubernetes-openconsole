package rbac

import (
	"sort"
	"testing"

	"k8s-dashboard/backend/internal/models"
)

func perm(cluster int, ns, resource, action string) models.NamespacePermission {
	return models.NamespacePermission{ClusterID: cluster, Namespace: ns, Resource: resource, Action: action}
}

func TestCanMatchesFullTuple(t *testing.T) {
	e := New([]models.NamespacePermission{
		perm(0, "team-a", "pods", "list"),
		perm(0, "team-a", "secrets", "get"),
	})
	cases := []struct {
		ns, resource, action string
		want                 bool
	}{
		{"team-a", "pods", "list", true},
		{"TEAM-A", "Pods", "LIST", true}, // case-insensitive
		{"team-a", "pods", "exec", false},
		{"team-a", "secrets", "get", true},
		{"team-a", "secrets", "reveal", false}, // get never implies reveal
		{"team-b", "pods", "list", false},
		{"team-a", "deployments", "list", false},
		{"", "pods", "list", false},
	}
	for _, c := range cases {
		if got := e.Can(1, c.ns, c.resource, c.action); got != c.want {
			t.Errorf("Can(%q,%q,%q) = %v, want %v", c.ns, c.resource, c.action, got, c.want)
		}
	}
}

func TestClusterScoping(t *testing.T) {
	e := New([]models.NamespacePermission{
		perm(1, "team-a", "pods", "list"), // only cluster 1
		perm(0, "shared", "pods", "list"), // every cluster
	})
	if !e.Can(1, "team-a", "pods", "list") {
		t.Error("cluster-1 grant must apply on cluster 1")
	}
	if e.Can(2, "team-a", "pods", "list") {
		t.Error("cluster-1 grant must not apply on cluster 2")
	}
	if !e.Can(2, "shared", "pods", "list") {
		t.Error("wildcard grant must apply on any cluster")
	}
	// No active cluster (0) falls back to wildcard matching by design.
	if !e.Can(0, "team-a", "pods", "list") {
		t.Error("cluster 0 (none active) should match cluster-scoped grants")
	}
}

func TestAllowedNamespacesAndResources(t *testing.T) {
	e := New([]models.NamespacePermission{
		perm(1, "team-a", "pods", "list"),
		perm(1, "team-a", "pods", "logs"),
		perm(2, "team-b", "pods", "list"),
		perm(0, "shared", "configmaps", "get"),
	})
	ns := e.AllowedNamespaces(1)
	sort.Strings(ns)
	if want := []string{"shared", "team-a"}; !equal(ns, want) {
		t.Errorf("AllowedNamespaces(1) = %v, want %v", ns, want)
	}
	res := e.AllowedResources(1, "team-a")
	if len(res) != 1 || len(res["pods"]) != 2 {
		t.Errorf("AllowedResources(1, team-a) = %v", res)
	}
	if res := e.AllowedResources(1, "team-b"); len(res) != 0 {
		t.Errorf("team-b is cluster-2 only, got %v on cluster 1", res)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
