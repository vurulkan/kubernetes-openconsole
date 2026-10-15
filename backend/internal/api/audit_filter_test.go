package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestAuditFacetsAndFilters(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, bob := e.user("bob", false)
	// Generates deployment.restart.denied (bob) and .success (root).
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", bob, nil, http.StatusForbidden)
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusOK)
	e.waitAudit("deployment.restart.success", "api")
	e.waitAudit("deployment.restart.denied", "api")

	out := e.expect("GET", "/api/admin/audit-logs/facets", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"deployment.restart"`) || !strings.Contains(out, `"bob"`) || !strings.Contains(out, `"team-a"`) ||
		!strings.Contains(out, `"verbs":["restart"]`) || !strings.Contains(out, `"resourceTypes":["deployment"]`) {
		t.Fatalf("facets = %s", out)
	}
	e.expect("GET", "/api/admin/audit-logs/facets", bob, nil, http.StatusForbidden)

	out = e.expect("GET", "/api/admin/audit-logs?action=deployment.*&outcome=denied", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":1`) || !strings.Contains(out, `"user":"bob"`) {
		t.Fatalf("family+outcome = %s", out)
	}
	out = e.expect("GET", "/api/admin/audit-logs?action=deployment.restart&actionExact=1", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":2`) {
		t.Fatalf("exact = %s", out)
	}
	// The pre-2.17 form still works: the outcome is split off.
	out = e.expect("GET", "/api/admin/audit-logs?action=deployment.restart.denied", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":1`) || !strings.Contains(out, `"reason":"forbidden"`) || !strings.Contains(out, `"verb":"restart"`) {
		t.Fatalf("legacy action = %s", out)
	}
	out = e.expect("GET", "/api/admin/audit-logs?verb=restart&outcome=success&resourceType=deployment", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":1`) || !strings.Contains(out, `"restarted_at"`) {
		t.Fatalf("verb filter = %s", out)
	}
	e.expect("GET", "/api/admin/audit-logs?verb=bogus", admin, nil, http.StatusBadRequest)
	e.expect("GET", "/api/admin/audit-logs?outcome=bogus", admin, nil, http.StatusBadRequest)
	csv := e.expect("GET", "/api/admin/audit-logs/export?outcome=success&action=deployment.*", admin, nil, http.StatusOK)
	if strings.Count(strings.TrimSpace(csv), "\n") != 1 || !strings.Contains(csv, "deployment.restart,restart,success,") ||
		!strings.HasPrefix(csv, "timestamp,user,action,verb,outcome,reason,") {
		t.Fatalf("export = %s", csv)
	}
}
