package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

// Clusters in newTestEnv: 1 = alpha (default), 2 = beta (own objects:
// namespace "beta-only", pod "beta-pod").

func TestEachUserWorksOnTheirOwnCluster(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, other := e.user("root2", true)

	// Both start on the default cluster (alpha).
	if out := e.expect("GET", "/api/namespaces", admin, nil, http.StatusOK); strings.Contains(out, "beta-only") {
		t.Fatalf("default should be alpha: %s", out)
	}
	e.expect("POST", "/api/cluster/select", admin, map[string]int{"clusterId": 2}, http.StatusOK)
	e.waitAudit("cluster.select.success", "beta")

	// The admin now reads beta…
	if out := e.expect("GET", "/api/namespaces", admin, nil, http.StatusOK); !strings.Contains(out, "beta-only") {
		t.Fatalf("admin should be on beta: %s", out)
	}
	if out := e.expect("GET", "/api/namespaces/team-a/pods", admin, nil, http.StatusOK); !strings.Contains(out, "beta-pod") {
		t.Fatalf("pods should come from beta: %s", out)
	}
	out := e.expect("GET", "/api/cluster/active", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"name":"beta"`) || !strings.Contains(out, `"isDefault":false`) {
		t.Fatalf("active = %s", out)
	}
	// …while another user is untouched by that choice.
	if out := e.expect("GET", "/api/namespaces", other, nil, http.StatusOK); strings.Contains(out, "beta-only") {
		t.Fatalf("another user's cluster changed: %s", out)
	}

	// Back to the default.
	e.expect("POST", "/api/cluster/select", admin, map[string]int{"clusterId": 0}, http.StatusOK)
	if out := e.expect("GET", "/api/namespaces", admin, nil, http.StatusOK); strings.Contains(out, "beta-only") {
		t.Fatalf("clusterId 0 should return to the default: %s", out)
	}
}

func TestClusterSelectionFollowsGrants(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{2, "team-a", "pods", "list"}) // beta only

	// Only beta is offered, and alpha can't be picked.
	out := e.expect("GET", "/api/clusters/public", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"name":"beta"`) || strings.Contains(out, `"name":"alpha"`) {
		t.Fatalf("public clusters = %s", out)
	}
	e.expect("POST", "/api/cluster/select", bob, map[string]int{"clusterId": 1}, http.StatusForbidden)
	e.waitAudit("cluster.select.denied", "alpha")
	e.expect("POST", "/api/cluster/select", bob, map[string]int{"clusterId": 99}, http.StatusNotFound)

	// On the default (alpha) the beta-only grant does nothing; on beta it does.
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusForbidden)
	e.expect("POST", "/api/cluster/select", bob, map[string]int{"clusterId": 2}, http.StatusOK)
	out = e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusOK)
	if !strings.Contains(out, "beta-pod") {
		t.Fatalf("pods = %s", out)
	}
	out = e.expect("GET", "/api/clusters/public", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"selected":true`) {
		t.Fatalf("beta should be marked selected: %s", out)
	}

	// Losing the grant drops the selection back to the default.
	_ = e.store.SetUserGroups(context.Background(), bobID, nil)
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusForbidden)
	if out := e.expect("GET", "/api/cluster/active", bob, nil, http.StatusOK); !strings.Contains(out, `"name":"alpha"`) {
		t.Fatalf("selection should fall back to the default: %s", out)
	}
}

func TestAuditRecordsTheCluster(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/cluster/select", admin, map[string]int{"clusterId": 2}, http.StatusOK)
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusOK)
	if got := e.waitAudit("deployment.restart.success", "api"); got.Cluster != "beta" {
		t.Fatalf("audit cluster = %q, want beta", got.Cluster)
	}
	out := e.expect("GET", "/api/admin/audit-logs?action=deployment.restart", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"cluster":"beta"`) {
		t.Fatalf("audit API should expose the cluster: %s", out)
	}
}

func TestDeletedClusterSelectionFallsBack(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/cluster/select", admin, map[string]int{"clusterId": 2}, http.StatusOK)
	e.expect("DELETE", "/api/admin/clusters/2", admin, nil, http.StatusOK)
	if out := e.expect("GET", "/api/cluster/active", admin, nil, http.StatusOK); !strings.Contains(out, `"name":"alpha"`) {
		t.Fatalf("after delete the admin should be back on the default: %s", out)
	}
}

// ─── Password reset ─────────────────────────────────────────────────────────

func TestPasswordResetLocalUsersOnly(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	ctx := context.Background()
	hash, _ := auth.HashPassword("Old-passw0rd")
	localID, _ := e.store.CreateUser(ctx, "carol", hash)
	carolTok := e.token(localID, "carol")
	ldapID, _ := e.store.CreateUser(ctx, "dirk", hash)
	_ = e.store.SetUserAuthSource(ctx, ldapID, models.AuthSourceLDAP)
	azureID, _ := e.store.CreateUser(ctx, "ann@example.com", hash)
	_ = e.store.SetUserAuthSource(ctx, azureID, models.AuthSourceAzure)

	path := func(id int) string { return "/api/admin/users/" + itoa(int64(id)) + "/reset-password" }

	e.expect("POST", path(localID), admin, map[string]string{"password": "short"}, http.StatusBadRequest)
	e.expect("POST", path(localID), admin, map[string]string{"password": "New-passw0rd"}, http.StatusOK)
	e.waitAudit("user.password_reset.success", "carol")

	// Sessions revoked, new password works, must change it at next login.
	e.expect("GET", "/api/cluster/active", carolTok, nil, http.StatusUnauthorized)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "carol", "password": "Old-passw0rd"}, http.StatusUnauthorized)
	out := e.expect("POST", "/api/auth/login", "", map[string]string{"username": "carol", "password": "New-passw0rd"}, http.StatusOK)
	if !strings.Contains(out, `"mustChangePassword":true`) {
		t.Fatalf("reset should force a password change: %s", out)
	}

	// Directory users are refused.
	e.expect("POST", path(ldapID), admin, map[string]string{"password": "New-passw0rd"}, http.StatusConflict)
	e.waitAudit("user.password_reset.failed", "source=ldap")
	e.expect("POST", path(azureID), admin, map[string]string{"password": "New-passw0rd"}, http.StatusConflict)

	// Non-admins are refused and audited.
	_, bob := e.user("bob", false)
	e.expect("POST", path(localID), bob, map[string]string{"password": "New-passw0rd"}, http.StatusForbidden)
	e.waitAudit("user.password_reset.denied", "")

	// The users list shows where each account signs in.
	out = e.expect("GET", "/api/admin/users", admin, nil, http.StatusOK)
	for _, want := range []string{`"username":"carol","mustChangePassword":true,"isActive":true,"isAdmin":false`, `"authSource":"ldap"`, `"authSource":"azure"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("users list missing %s: %s", want, out)
		}
	}
}

func TestLDAPImportMarksUsersLDAP(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/admin/ldap/users/import", admin, map[string][]string{"usernames": {"jdoe"}}, http.StatusOK)
	u, err := e.store.GetUserByUsername(context.Background(), "jdoe")
	if err != nil || u.AuthSource != models.AuthSourceLDAP {
		t.Fatalf("imported user = %+v, err %v", u, err)
	}
	e.expect("POST", "/api/admin/users/"+itoa(int64(u.ID))+"/reset-password", admin, map[string]string{"password": "New-passw0rd"}, http.StatusConflict)
}
