package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/rbac"
)

// Every key an operation may have; another one is a YAML slip (an unquoted comma in a
// flow mapping splits the value into keys).
var openapiOpKeys = []string{"tags", "summary", "description", "security", "parameters", "requestBody", "responses",
	"x-openconsole-permission", "x-openconsole-admin", "x-openconsole-api-key"}

type openapiOp struct {
	Tags       []string `json:"tags"`
	Summary    string   `json:"summary"`
	Permission []string `json:"x-openconsole-permission"`
	Admin      bool     `json:"x-openconsole-admin"`
}

var openapiTags = []string{"Account", "Workloads", "Pods", "Logs", "Exec", "Config", "Events", "Admin"}

// Every /api and /ws route is in openapi.yaml and every operation there is a route:
// a new endpoint without its description fails here (CLAUDE.md "When you add an endpoint").
func TestOpenAPIMatchesRouter(t *testing.T) {
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Tags    []map[string]any                      `json:"tags"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.1") {
		t.Fatalf("openapi = %q, want 3.1.x", spec.OpenAPI)
	}
	for _, tag := range spec.Tags {
		if len(tag) != 2 || tag["name"] == nil || tag["description"] == nil {
			t.Errorf("tag %v: wants name and description only (quote values with commas)", tag)
		}
	}
	inSpec := map[string]openapiOp{}
	for path, item := range spec.Paths {
		for method, raw := range item {
			if method == "parameters" {
				continue
			}
			var op openapiOp
			var keys map[string]json.RawMessage
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			_ = json.Unmarshal(raw, &keys)
			for k := range keys {
				if !slices.Contains(openapiOpKeys, k) {
					t.Errorf("%s %s: unexpected key %q (quote values with commas)", method, path, k)
				}
			}
			inSpec[strings.ToUpper(method)+" "+path] = op
		}
	}
	routes := map[string]bool{}
	s := &Server{}
	err := chi.Walk(s.routes(), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/api/") || strings.HasPrefix(route, "/ws/") {
			routes[method+" "+route] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var missing, stale []string
	for r := range routes {
		if _, ok := inSpec[r]; !ok {
			missing = append(missing, r)
		}
	}
	for r, op := range inSpec {
		if !routes[r] {
			stale = append(stale, r)
			continue
		}
		path := strings.SplitN(r, " ", 2)[1]
		if len(op.Tags) != 1 || !slices.Contains(openapiTags, op.Tags[0]) || op.Summary == "" {
			t.Errorf("%s: wants one tag of %v and a summary", r, openapiTags)
		}
		if admin := strings.HasPrefix(path, "/api/admin/"); admin != op.Admin || admin != (op.Tags[0] == "Admin") {
			t.Errorf("%s: x-openconsole-admin and the Admin tag go with /api/admin/ paths only", r)
		}
		for _, p := range op.Permission {
			resource, action, _ := strings.Cut(p, ":")
			if !(resource == "*" && action == "edit") && !inCatalog(resource, action) {
				t.Errorf("%s: permission %q is not in rbac.Catalog", r, p)
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("routes missing from openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("openapi.yaml operations with no route:\n  %s", strings.Join(stale, "\n  "))
	}
}

func inCatalog(resource, action string) bool {
	for _, c := range rbac.Catalog {
		if c.Resource == resource && slices.Contains(c.Actions, action) {
			return true
		}
	}
	return false
}
