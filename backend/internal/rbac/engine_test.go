package rbac

import (
	"sort"
	"strings"
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

// An API key gets what it lists ∩ what its owner holds now, evaluated per call.
func TestKeyIntersection(t *testing.T) {
	user := []models.NamespacePermission{
		perm(0, "team-a", "pods", "list"),
		perm(0, "team-a", "pods", "exec"),
		perm(1, "team-b", "pods", "list"),
		perm(2, "team-c", "pods", "list"),
	}
	key := &models.APIKeyScope{Clusters: []int{1}, Namespaces: []string{"team-a", "team-b", "team-c"},
		Grants: []string{"pods:list", "secrets:reveal"}}
	e := New(user).WithKey(key)
	cases := []struct {
		cluster              int
		ns, resource, action string
		want                 bool
	}{
		{1, "team-a", "pods", "list", true},       // all-clusters grant, narrowed to the key's cluster
		{2, "team-a", "pods", "list", false},      // not a key cluster
		{1, "team-a", "pods", "exec", false},      // user has it, key does not
		{1, "team-a", "secrets", "reveal", false}, // key lists it, user does not
		{1, "team-b", "pods", "list", true},
		{1, "team-c", "pods", "list", false}, // user's grant is for cluster 2 only
		{1, "team-d", "pods", "list", false},
	}
	for _, c := range cases {
		if got := e.Can(c.cluster, c.ns, c.resource, c.action); got != c.want {
			t.Errorf("Can(%d,%q,%q,%q) = %v, want %v", c.cluster, c.ns, c.resource, c.action, got, c.want)
		}
	}
	if !e.CoversCluster(1) || e.CoversCluster(2) {
		t.Error("key on cluster 1 must cover 1 only")
	}

	// "All my namespaces" follows the user: a namespace granted later is in, one taken away is out.
	all := &models.APIKeyScope{Clusters: []int{0}, AllNamespaces: true, Grants: []string{"pods:list"}}
	if !New(user).WithKey(all).Can(2, "team-c", "pods", "list") {
		t.Error("all namespaces should reach team-c on cluster 2")
	}
	later := append(user, perm(0, "team-new", "pods", "list"))
	if !New(later).WithKey(all).Can(1, "team-new", "pods", "list") {
		t.Error("a namespace granted later is part of all namespaces")
	}
	if New(user[:1]).WithKey(all).Can(1, "team-b", "pods", "list") {
		t.Error("a grant the user lost must be gone for the key too")
	}
}

func TestAdminEngineWithKey(t *testing.T) {
	admin := NewAdmin()
	if !admin.Can(5, "anything", "secrets", "reveal") || !admin.SeesNamespace(5, "x") || !admin.CoversCluster(9) {
		t.Fatal("admin holds every grant")
	}
	if got := admin.AllowedResources(1, "x")["secrets"]; strings.Join(got, ",") != "list,get,reveal,edit" {
		t.Fatalf("admin secrets = %v", got)
	}
	k := admin.WithKey(&models.APIKeyScope{Clusters: []int{2}, Namespaces: []string{"ns1"}, Grants: []string{"pods:list"}})
	if !k.Can(2, "ns1", "pods", "list") || k.Can(2, "ns1", "pods", "exec") || k.Can(1, "ns1", "pods", "list") || k.Can(2, "ns2", "pods", "list") {
		t.Fatal("admin key must stay inside its scope")
	}
	if !k.SeesNamespace(2, "ns1") || k.SeesNamespace(2, "ns2") || k.CoversCluster(1) {
		t.Fatal("admin key namespaces / clusters")
	}
	if got := k.AllowedResources(2, "ns1"); len(got) != 1 || len(got["pods"]) != 1 {
		t.Fatalf("admin key resources = %v", got)
	}
}
