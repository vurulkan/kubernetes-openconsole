package api

import (
	"net/http"
	"strings"
	"testing"
)

func withDisabledFeatures(t *testing.T, off ...string) {
	t.Helper()
	prev := disabledFeatures
	SetDisabledFeatures(off)
	t.Cleanup(func() { disabledFeatures = prev })
}

func TestFeatureFlagsBlockEvenAdmins(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	withDisabledFeatures(t, FeaturePodExec, FeatureSecretReveal, FeatureWorkloadActions)

	// Hidden from the UI's permission map…
	out := e.expect("GET", "/api/namespaces/team-a/permissions", admin, nil, http.StatusOK)
	for _, gone := range []string{`"exec"`, `"reveal"`, `"restart"`} {
		if strings.Contains(out, gone) {
			t.Fatalf("%s should be filtered out: %s", gone, out)
		}
	}
	if !strings.Contains(out, `"secrets":["list","get","edit"]`) {
		t.Fatalf("other secrets actions should stay: %s", out)
	}
	// …and refused (and audited) at the endpoint.
	e.expect("GET", "/ws/namespaces/team-a/pods/api-1/exec", admin, nil, http.StatusForbidden)
	e.waitAudit("pod.exec.denied", "api-1")
	e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", admin, map[string]string{"key": "password"}, http.StatusForbidden)
	e.waitAudit("secret.reveal.denied", "db")
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusForbidden)
	e.waitAudit("deployment.restart.denied", "api")
	// Untouched features keep working.
	e.expect("GET", "/api/namespaces/team-a/secrets", admin, nil, http.StatusOK)

	out = e.expect("GET", "/api/features", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"pod_exec":false`) || !strings.Contains(out, `"yaml_edit":true`) {
		t.Fatalf("features = %s", out)
	}
}

func TestSecretsFeatureOffHidesTheTab(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	withDisabledFeatures(t, FeatureSecrets)
	if out := e.expect("GET", "/api/namespaces/team-a/permissions", admin, nil, http.StatusOK); strings.Contains(out, "secrets") {
		t.Fatalf("secrets should be gone: %s", out)
	}
	e.expect("GET", "/api/namespaces/team-a/secrets", admin, nil, http.StatusForbidden)
	e.expect("GET", "/api/namespaces/team-a/secrets/db/yaml", admin, nil, http.StatusForbidden)
}

func TestFeatureAllowsMapping(t *testing.T) {
	withDisabledFeatures(t, FeatureYAMLEdit)
	cases := []struct {
		res, act string
		want     bool
	}{
		{"deployments", "edit", false},
		{"configmaps", "edit", false},
		{"secrets", "edit", true}, // governed by secret_edit, not yaml_edit
		{"pods", "list", true},
		{"pods", "exec", true},
	}
	for _, c := range cases {
		if got := featureAllows(c.res, c.act); got != c.want {
			t.Errorf("featureAllows(%s, %s) = %v, want %v", c.res, c.act, got, c.want)
		}
	}
}
