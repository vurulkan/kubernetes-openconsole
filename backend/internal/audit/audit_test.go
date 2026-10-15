package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

func TestUpgradeLegacyEntry(t *testing.T) {
	cases := []struct {
		in                                    models.AuditLog
		action, verb, outcome, kind, name, ns string
	}{
		{models.AuditLog{Action: "list", ResourceType: "deployments", ResourceName: "*", Namespace: "boh-cy"},
			"deployment.list", "list", "success", "deployment", "*", "boh-cy"},
		{models.AuditLog{Action: "list", ResourceType: "namespaces", ResourceName: "*", Namespace: "-"},
			"namespace.list", "list", "success", "namespace", "*", ""},
		{models.AuditLog{Action: "logs", ResourceType: "pods", ResourceName: "api-1"},
			"pod.logs", "logs", "success", "pod", "api-1", ""},
		{models.AuditLog{Action: "deployment.restart.success", ResourceType: "deployment", ResourceName: "boh (restartedAt=x)"},
			"deployment.restart", "restart", "success", "deployment", "boh (restartedAt=x)", ""},
		{models.AuditLog{Action: "statefulset.scale.rate_limited", ResourceType: "statefulset"},
			"statefulset.scale", "scale", "rate_limited", "statefulset", "", ""},
		{models.AuditLog{Action: "deployments.apply.denied", ResourceType: "deployments"},
			"deployment.apply", "apply", "denied", "deployment", "", ""},
		{models.AuditLog{Action: "secret.yaml.view.failed", ResourceType: "secret"},
			"secret.view_yaml", "view_yaml", "failed", "secret", "", ""},
		{models.AuditLog{Action: "pod.exec.start", ResourceType: "pod"},
			"pod.exec", "exec", "success", "pod", "", ""},
		{models.AuditLog{Action: "pod.exec.session.record_skipped", ResourceType: "pod"},
			"recording.create", "create", "failed", "recording", "", ""},
		{models.AuditLog{Action: "login.locked", ResourceType: "auth", ResourceName: "local", Namespace: "-"},
			"user.login", "login", "locked", "user", "local", ""},
		{models.AuditLog{Action: "login.azure", ResourceType: "auth"},
			"user.login", "login", "success", "user", "", ""},
		{models.AuditLog{Action: "admin.create", ResourceType: "users", ResourceName: "ali (source=local)"},
			"user.create", "create", "success", "user", "ali (source=local)", ""},
		{models.AuditLog{Action: "admin.update", ResourceType: "ldap", ResourceName: "config"},
			"settings.update", "update", "success", "settings", "ldap", ""},
		{models.AuditLog{Action: "admin.update", ResourceType: "customization", ResourceName: "logo_removed"},
			"settings.delete", "delete", "success", "settings", "logo", ""},
		{models.AuditLog{Action: "admin.add_permission", ResourceType: "roles", ResourceName: "3"},
			"permission.create", "create", "success", "permission", "3", ""},
		{models.AuditLog{Action: "recording.settings.update.denied", ResourceType: "recording", ResourceName: "settings"},
			"settings.update", "update", "denied", "settings", "recording", ""},
		{models.AuditLog{Action: "cluster.select.success", ResourceType: "cluster", ResourceName: "beta"},
			"cluster.select", "select", "success", "cluster", "beta", ""},
		{models.AuditLog{Action: "view.change.denied", ResourceType: "view"},
			"saved_view.update", "update", "denied", "saved_view", "", ""},
		{models.AuditLog{Action: "user.password_reset.failed", ResourceType: "user"},
			"user.reset_password", "reset_password", "failed", "user", "", ""},
		{models.AuditLog{Action: "change_password", ResourceType: "users"},
			"user.change_password", "change_password", "success", "user", "", ""},
	}
	for _, c := range cases {
		got := UpgradeLegacyEntry(c.in)
		if got.Action != c.action || got.Verb != c.verb || got.Outcome != c.outcome ||
			got.ResourceType != c.kind || got.ResourceName != c.name || got.Namespace != c.ns {
			t.Errorf("%s → %+v", c.in.Action, got)
		}
	}
}

// A 2.16 database: the audit columns are added, old rows are upgraded on
// start (once), and the new filters find them.
func TestUpgradeLegacyRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL,
			user TEXT NOT NULL, action TEXT NOT NULL, namespace TEXT NOT NULL,
			resource_type TEXT NOT NULL, resource_name TEXT NOT NULL, cluster TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO audit_logs (timestamp, user, action, namespace, resource_type, resource_name, cluster) VALUES
			('2026-10-14 10:00:00', 'ali', 'deployment.scale.success', 'team-a', 'deployment', 'api (from=1 to=3)', 'prod'),
			('2026-10-14 10:01:00', 'ali', 'list', 'team-a', 'pods', '*', 'prod'),
			('2026-10-14 10:02:00', 'bob', 'login.failed', '-', 'auth', 'bad_password', '')`,
	} {
		if _, err := legacy.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	legacy.Close()

	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Conn.Close()
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	l := New(st)
	ctx := context.Background()
	if err := l.UpgradeLegacy(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ := st.LegacyAuditLogs(ctx, 10); len(rows) != 0 {
		t.Fatalf("left over: %+v", rows)
	}
	count := func(f store.AuditFilter) int {
		n, _ := st.CountAuditLogsFiltered(ctx, f)
		return n
	}
	if count(store.AuditFilter{Verb: VerbScale, Outcome: Success}) != 1 ||
		count(store.AuditFilter{Action: "pod.list", ActionExact: true}) != 1 ||
		count(store.AuditFilter{Action: "user.login", Outcome: Failed}) != 1 {
		logs, _ := st.ListAuditLogsFiltered(ctx, 10, 0, store.AuditFilter{})
		t.Fatalf("upgraded rows = %+v", logs)
	}
	if err := l.UpgradeLegacy(ctx); err != nil { // nothing left: no-op
		t.Fatal(err)
	}
}

func TestNormalizeDetails(t *testing.T) {
	e := models.AuditLog{
		ResourceType: "deployment", Verb: VerbScale, Namespace: "-",
		Details: D{"replicas_from": int32(1), "replicas_to": 3, "bogus": "x", "error": "", "started_at": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	}
	normalize(&e)
	if e.Action != "deployment.scale" || e.Outcome != Success || e.Namespace != "" {
		t.Fatalf("event = %+v", e)
	}
	want := D{"replicas_from": int64(1), "replicas_to": int64(3), "started_at": "2026-01-02T03:04:05Z"}
	if len(e.Details) != len(want) {
		t.Fatalf("details = %v", e.Details)
	}
	for k, v := range want {
		if e.Details[k] != v {
			t.Fatalf("details[%s] = %#v, want %#v", k, e.Details[k], v)
		}
	}
}

// Every verb has an ECS event.type, so dashboards can rely on it.
func TestEveryVerbHasECSType(t *testing.T) {
	for _, v := range Verbs {
		if logging.AuditEventType(v, "") == "" {
			t.Errorf("verb %q has no event.type", v)
		}
	}
}

// The console line: one record with the fields as their own ECS fields and
// details flat under openconsole.*.
func TestConsoleLineECS(t *testing.T) {
	var buf bytes.Buffer
	h := slog.New(logging.NewECSHandler(&buf, nil))
	e := models.AuditLog{
		User: "mustafa@corp.com", Verb: VerbRestart, ResourceType: "deployment", ResourceName: "boh",
		Namespace: "boh-cy", Cluster: "Zenia-NonProd", ClusterID: 2, RequestID: "r1", SourceIP: "10.1.2.3",
		UserAgent: "Firefox", AuthSource: "azure", Details: D{"restarted_at": "2026-10-15T14:55:22Z"},
	}
	normalize(&e)
	h.LogAttrs(context.Background(), slog.LevelInfo, "audit", consoleAttrs(e)...)
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	get := func(path string) any {
		var cur any = rec
		for _, p := range strings.Split(path, ".") {
			cur = cur.(map[string]any)[p]
		}
		return cur
	}
	for path, want := range map[string]any{
		"message":                   "mustafa@corp.com: deployment.restart success boh-cy/boh on Zenia-NonProd",
		"event.action":              "deployment.restart",
		"event.outcome":             "success",
		"event.dataset":             "openconsole.audit",
		"user.name":                 "mustafa@corp.com",
		"source.ip":                 "10.1.2.3",
		"user_agent.original":       "Firefox",
		"http.request.id":           "r1",
		"openconsole.verb":          "restart",
		"openconsole.outcome":       "success",
		"openconsole.cluster":       "Zenia-NonProd",
		"openconsole.cluster_id":    float64(2),
		"openconsole.namespace":     "boh-cy",
		"openconsole.resource_type": "deployment",
		"openconsole.resource_name": "boh",
		"openconsole.auth_source":   "azure",
		"openconsole.restarted_at":  "2026-10-15T14:55:22Z",
	} {
		if got := get(path); got != want {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if typ := get("event.type").([]any); len(typ) != 1 || typ[0] != "change" {
		t.Errorf("event.type = %v", typ)
	}
	if cat := get("event.category").([]any); len(cat) != 1 || cat[0] != "configuration" {
		t.Errorf("event.category = %v", cat)
	}
}

// Every details key and every console field under openconsole.* has a
// mapping in deploy/elk with the registered type, so Elasticsearch never
// guesses one (a date as text, a count as keyword).
func TestElasticMappingCoversDetails(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/elk/openconsole@mappings.component-template.json")
	if err != nil {
		t.Fatal(err)
	}
	var tmpl struct {
		Template struct {
			Mappings struct {
				Properties map[string]struct {
					Properties map[string]struct {
						Type string `json:"type"`
					} `json:"properties"`
				} `json:"properties"`
			} `json:"mappings"`
		} `json:"template"`
	}
	if err := json.Unmarshal(raw, &tmpl); err != nil {
		t.Fatal(err)
	}
	oc := tmpl.Template.Mappings.Properties["openconsole"].Properties
	esType := map[DetailType]string{Keyword: "keyword", Long: "long", Bool: "boolean", Date: "date", Text: "match_only_text"}
	for k, typ := range DetailKeys {
		if k == "error" { // error.message
			continue
		}
		if got := oc[k].Type; got != esType[typ] {
			t.Errorf("openconsole.%s mapped as %q, want %q", k, got, esType[typ])
		}
	}
	for _, k := range []string{"verb", "outcome", "auth_source", "cluster", "namespace", "resource_type", "resource_name"} {
		if oc[k].Type != "keyword" {
			t.Errorf("openconsole.%s mapped as %q", k, oc[k].Type)
		}
	}
	if oc["cluster_id"].Type != "long" {
		t.Errorf("openconsole.cluster_id mapped as %q", oc["cluster_id"].Type)
	}
}
