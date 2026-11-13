package rbac

import (
	"testing"

	"k8s-dashboard/backend/internal/models"
)

// What an API key may reach under the admin policy: each role's rows through
// its mode, the override replacing every mode, an admin by override only.
func TestKeyCeiling(t *testing.T) {
	// Role 1 ("full") in ns1, role 2 ("safe_read") in ns2, role 3 ("off") in ns3.
	var perms []models.NamespacePermission
	for _, r := range []struct {
		role int
		mode string
		ns   string
	}{{1, AccessFull, "ns1"}, {2, AccessSafeRead, "ns2"}, {3, AccessOff, "ns3"}} {
		for _, g := range [][2]string{{"pods", "list"}, {"pods", "exec"}, {"secrets", "list"}} {
			perms = append(perms, models.NamespacePermission{RoleID: r.role, Namespace: r.ns, Resource: g[0], Action: g[1], RoleAPIAccess: r.mode})
		}
	}
	grants := [][2]string{{"pods", "list"}, {"pods", "exec"}, {"secrets", "list"}}
	// Rows: ns1..ns3, columns: pods:list, pods:exec, secrets:list.
	for _, c := range []struct {
		override string
		want     [3][3]bool
	}{
		{"", [3][3]bool{{true, true, true}, {true, false, false}, {false, false, false}}},
		{AccessOff, [3][3]bool{}},
		{AccessSafeRead, [3][3]bool{{true, false, false}, {true, false, false}, {true, false, false}}},
		{AccessFull, [3][3]bool{{true, true, true}, {true, true, true}, {true, true, true}}},
	} {
		e := New(KeyCeiling(perms, c.override))
		for i, ns := range []string{"ns1", "ns2", "ns3"} {
			for j, g := range grants {
				if got := e.Can(1, ns, g[0], g[1]); got != c.want[i][j] {
					t.Errorf("override %q: %s %s:%s = %v", c.override, ns, g[0], g[1], got)
				}
			}
		}
	}
	// "full" never reaches beyond the web grants.
	if New(KeyCeiling(perms, AccessFull)).Can(1, "ns4", "pods", "list") {
		t.Error("full override reached a namespace the user does not have")
	}
}

func TestAdminKeys(t *testing.T) {
	key := &models.APIKeyScope{Clusters: []int{0}, AllNamespaces: true, Grants: []string{"pods:list", "pods:exec", "secrets:reveal"}}
	for _, c := range []struct {
		override               string
		list, exec, reveal, ns bool
	}{
		{"", true, true, true, true},
		{AccessFull, true, true, true, true},
		{AccessSafeRead, true, false, false, true},
		{AccessOff, false, false, false, false},
	} {
		e := NewAdminKeys(c.override).WithKey(key)
		got := [4]bool{e.Can(1, "x", "pods", "list"), e.Can(1, "x", "pods", "exec"), e.Can(1, "x", "secrets", "reveal"), e.SeesNamespace(1, "x")}
		if got != [4]bool{c.list, c.exec, c.reveal, c.ns} {
			t.Errorf("admin override %q: list/exec/reveal/ns = %v", c.override, got)
		}
		if AdminScopeAllowed(c.override) != (c.override == "" || c.override == AccessFull) {
			t.Errorf("admin scope with override %q", c.override)
		}
	}
	// The web session of an admin is never limited.
	if !NewAdmin().Can(1, "x", "pods", "exec") {
		t.Error("admin web session lost exec")
	}
}

func TestSafeRead(t *testing.T) {
	for g, want := range map[[2]string]bool{
		{"pods", "list"}: true, {"pods", "logs"}: true, {"deployments", "get"}: true,
		{"pods", "exec"}: false, {"deployments", "scale"}: false, {"configmaps", "get"}: false,
		{"secrets", "list"}: false, {"secrets", "reveal"}: false, {"services", "edit"}: false,
	} {
		if SafeRead(g[0], g[1]) != want {
			t.Errorf("SafeRead(%v) = %v", g, !want)
		}
	}
	for _, g := range SafeReadGrants() {
		if g == "configmaps:list" || g == "pods:exec" {
			t.Errorf("SafeReadGrants has %s", g)
		}
	}
}
