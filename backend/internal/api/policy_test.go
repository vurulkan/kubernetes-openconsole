package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/auth"
)

func TestPasswordPolicy(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)

	e.expect("POST", "/api/admin/users", admin, map[string]string{"username": "short", "password": "abc"}, http.StatusBadRequest)
	e.expect("POST", "/api/admin/users", admin, map[string]string{"username": "  ", "password": "Long-enough-1"}, http.StatusBadRequest)
	e.expect("POST", "/api/admin/users", admin, map[string]string{"username": "ok", "password": "Long-enough-1"}, http.StatusCreated)
	e.expect("POST", "/api/admin/users", admin, map[string]string{"username": "ok", "password": "Long-enough-1"}, http.StatusConflict)

	hash, _ := auth.HashPassword("Current-pass-1")
	id, _ := e.store.CreateUser(context.Background(), "carol", hash)
	tok := e.token(id, "carol")
	e.expect("POST", "/api/auth/change-password", tok, map[string]string{"currentPassword": "Current-pass-1", "newPassword": "abc"}, http.StatusBadRequest)
	e.expect("POST", "/api/auth/change-password", tok, map[string]string{"currentPassword": "Current-pass-1", "newPassword": "Current-pass-1"}, http.StatusBadRequest)
	e.expect("POST", "/api/auth/change-password", tok, map[string]string{"currentPassword": "wrong", "newPassword": "Brand-new-pass-2"}, http.StatusUnauthorized)
	e.expect("POST", "/api/auth/change-password", tok, map[string]string{"currentPassword": "Current-pass-1", "newPassword": "Brand-new-pass-2"}, http.StatusOK)
}

func TestExecConcurrentSessionLimit(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "exec"})

	prev := maxExecSessionsPerUser
	maxExecSessionsPerUser = 2
	t.Cleanup(func() { maxExecSessionsPerUser = prev })

	// Two shells already open for bob.
	for i := 0; i < 2; i++ {
		if !e.server.execSessions.acquire(bobID) {
			t.Fatal("acquire within the limit failed")
		}
	}
	e.expect("GET", "/ws/namespaces/team-a/pods/api-1/exec", bob, nil, http.StatusTooManyRequests)
	e.waitAudit("pod.exec.rate_limited", "max_sessions=2")

	// Closing one frees a slot (the request then proceeds past the limit and
	// fails later only because this plain GET is not a WebSocket upgrade).
	e.server.execSessions.release(bobID)
	if code, _ := e.do("GET", "/ws/namespaces/team-a/pods/api-1/exec", bob, nil); code == http.StatusTooManyRequests {
		t.Fatal("a released slot should be usable again")
	}
	e.server.execSessions.release(bobID)
}

func TestUserAndGroupCSVExport(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})

	out := e.expect("GET", "/api/admin/users/export", admin, nil, http.StatusOK)
	if !strings.HasPrefix(out, "username,source,admin,active,must_change_password,groups,created_at\n") ||
		!strings.Contains(out, "bob,local,false,true,false,group-") {
		t.Fatalf("users.csv = %s", out)
	}
	out = e.expect("GET", "/api/admin/groups/export", admin, nil, http.StatusOK)
	if !strings.HasPrefix(out, "group,members,roles\n") || !strings.Contains(out, ",bob,role-") {
		t.Fatalf("groups.csv = %s", out)
	}
	e.waitAudit("admin.export", "")
	e.expect("GET", "/api/admin/users/export", bob, nil, http.StatusForbidden)
}
