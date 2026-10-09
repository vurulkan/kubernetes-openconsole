package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSavedViews(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, alice := e.user("alice", false)
	_, bob := e.user("bob", false)

	view := map[string]any{"name": "payments pods", "namespace": "team-a", "tab": "pods", "search": "label:app=api", "viewMode": "list"}
	e.expect("POST", "/api/views", alice, view, http.StatusOK)
	e.waitAudit("view.save", "payments pods")
	// Saving the same name again replaces it instead of duplicating.
	view["search"] = "label:app=web"
	e.expect("POST", "/api/views", alice, view, http.StatusOK)
	out := e.expect("GET", "/api/views", alice, nil, http.StatusOK)
	if strings.Count(out, `"name":"payments pods"`) != 1 || !strings.Contains(out, "label:app=web") || !strings.Contains(out, `"clusterName":"alpha"`) || !strings.Contains(out, `"mine":true`) {
		t.Fatalf("alice views = %s", out)
	}
	e.expect("POST", "/api/views", alice, map[string]any{"name": "  "}, http.StatusBadRequest)

	// Private views are invisible (and untouchable) for others.
	if out := e.expect("GET", "/api/views", bob, nil, http.StatusOK); strings.Contains(out, "payments pods") {
		t.Fatalf("bob sees a private view: %s", out)
	}
	e.expect("DELETE", "/api/views/1", bob, nil, http.StatusNotFound)

	// Shared: visible to bob with the owner, still read-only for him.
	e.expect("PUT", "/api/views/1", alice, map[string]bool{"shared": true}, http.StatusOK)
	out = e.expect("GET", "/api/views", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"owner":"alice"`) || !strings.Contains(out, `"mine":false`) {
		t.Fatalf("bob should see alice's shared view: %s", out)
	}
	e.expect("PUT", "/api/views/1", bob, map[string]bool{"shared": false}, http.StatusForbidden)
	e.waitAudit("view.change.denied", "payments pods")
	e.expect("DELETE", "/api/views/1", bob, nil, http.StatusForbidden)

	// Admins can remove a shared view.
	e.expect("DELETE", "/api/views/1", admin, nil, http.StatusOK)
	e.waitAudit("view.delete", "owner=alice")
	if out := e.expect("GET", "/api/views", alice, nil, http.StatusOK); strings.Contains(out, "payments pods") {
		t.Fatalf("view should be gone: %s", out)
	}
}
