package api

import (
	"net/http"
	"testing"
)

// A cluster write refused because the request itself is wrong (body, value
// out of range, YAML that doesn't parse or names another object) is audited
// as failed with reason "invalid". Before 2.23.1 these answers left no entry.
func TestInvalidWriteRequestsAreAudited(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID,
		[4]any{0, "team-a", "deployments", "scale"},
		[4]any{0, "team-a", "deployments", "edit"},
		[4]any{0, "team-a", "statefulsets", "scale"},
		[4]any{0, "team-a", "pods", "exec"},
		[4]any{0, "team-a", "secrets", "reveal"},
	)
	cases := []struct {
		path   string
		body   any
		status int
		audit  string
		name   string
	}{
		{"/api/namespaces/team-a/deployments/api/scale", "not an object", http.StatusBadRequest, "deployment.scale.failed", "api"},
		{"/api/namespaces/team-a/deployments/web/scale", map[string]any{"replicas": -1}, http.StatusBadRequest, "deployment.scale.failed", "web"},
		{"/api/namespaces/team-a/statefulsets/db/scale", map[string]any{"replicas": 100000}, http.StatusBadRequest, "statefulset.scale.failed", "db"},
		{"/api/namespaces/team-a/deployments/api/apply", map[string]any{"yaml": ""}, http.StatusBadRequest, "deployment.apply.failed", "api"},
		{"/api/namespaces/team-a/deployments/web/apply", map[string]any{"yaml": "kind: [oops"}, http.StatusUnprocessableEntity, "deployment.apply.failed", "web"},
		{"/api/namespaces/team-a/deployments/cache/apply", map[string]any{"yaml": "metadata:\n  name: other\n"}, http.StatusUnprocessableEntity, "deployment.apply.failed", "cache"},
		{"/api/namespaces/team-a/pods/p1/exec", map[string]any{"command": []string{}}, http.StatusBadRequest, "pod.exec.failed", "p1"},
		{"/api/namespaces/team-a/secrets/db/reveal", map[string]any{}, http.StatusBadRequest, "secret.reveal.failed", "db"},
	}
	for _, c := range cases {
		e.expect("POST", c.path, bob, c.body, c.status)
		got := e.waitAudit(c.audit, c.name)
		if got.Reason != "invalid" {
			t.Fatalf("%s: reason %q (%s), want invalid", c.path, got.Reason, got.ResourceName)
		}
	}
}
