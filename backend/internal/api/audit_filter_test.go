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
	if !strings.Contains(out, `"deployment.restart.denied"`) || !strings.Contains(out, `"bob"`) || !strings.Contains(out, `"team-a"`) {
		t.Fatalf("facets = %s", out)
	}
	e.expect("GET", "/api/admin/audit-logs/facets", bob, nil, http.StatusForbidden)

	out = e.expect("GET", "/api/admin/audit-logs?action=deployment.*&outcome=denied", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":1`) || !strings.Contains(out, `"user":"bob"`) {
		t.Fatalf("family+outcome = %s", out)
	}
	out = e.expect("GET", "/api/admin/audit-logs?action=deployment.restart&actionExact=1", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"total":0`) {
		t.Fatalf("exact = %s", out)
	}
	e.expect("GET", "/api/admin/audit-logs?outcome=bogus", admin, nil, http.StatusBadRequest)
	csv := e.expect("GET", "/api/admin/audit-logs/export?outcome=success&action=deployment.*", admin, nil, http.StatusOK)
	if strings.Count(strings.TrimSpace(csv), "\n") != 1 || !strings.Contains(csv, "deployment.restart.success") {
		t.Fatalf("export = %s", csv)
	}
}
