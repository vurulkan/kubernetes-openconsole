package main

import (
	"strings"
	"testing"
)

// The scanner must find actions behind helpers (recordDeployAudit), closures
// (refuse := func(outcome, …)), event variables passed to denyAPIKey and
// permission checks for any resource.
func TestScanAuditActions(t *testing.T) {
	got, err := scanAuditActions("../../internal/audit", "../../internal/api", "../../internal/recording")
	if err != nil {
		t.Fatal(err)
	}
	for action, outcomes := range map[string][]string{
		"deployment.restart": {"success", "denied", "failed", "rate_limited"},
		"api_key.use":        {"denied", "rate_limited"},
		"api_key.export":     {"success", "denied", "failed"},
		"pod.logs":           {"success", "denied", "failed", "rate_limited"},
		"recording.evict":    {"success"},
		"user.login":         {"success", "failed", "locked"},
		"<resource>.apply":   {"success", "denied", "failed", "rate_limited"},
	} {
		for _, o := range outcomes {
			if !got[action][o] {
				t.Errorf("%s: outcome %s not found (have %v)", action, o, got[action])
			}
		}
	}
	if got["api_key.use"]["success"] {
		t.Error("api_key.use is only recorded when refused")
	}
}

func TestClusterRoleRules(t *testing.T) {
	rules, err := clusterRoleRules("../../../deploy/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var optional int
	for _, r := range rules {
		if r.about == "" || len(r.Verbs) == 0 {
			t.Errorf("rule %v: no description or verbs", r.Resources)
		}
		if r.optional {
			optional++
			if !strings.Contains(r.about, "Prometheus") {
				t.Errorf("optional rule %v: %q", r.Resources, r.about)
			}
		}
	}
	if optional != 1 {
		t.Errorf("want the commented-out services/proxy rule as optional, got %d", optional)
	}
}
