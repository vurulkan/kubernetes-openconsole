package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"k8s.io/klog/v2"
)

func ecsLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(newECSHandler(buf, nil)).With(slog.String("service", "openconsole"),
		slog.String("version", "2.16.2"), slog.String("env", "prod"))
}

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

// get reads a dotted path from nested maps.
func get(m map[string]any, path string) any {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[p]
	}
	return cur
}

func TestECSHTTPRecord(t *testing.T) {
	var buf bytes.Buffer
	ecsLogger(&buf).Warn("http.request",
		slog.String("method", "GET"), slog.String("path", "/api/auth/me"), slog.Int("status", 401),
		slog.Int64("duration_ns", 509909), slog.String("remote_ip", "10.31.67.52"),
		slog.String("request_id", "r1"), slog.String("user_agent", "Firefox"), slog.Int64("response_bytes", 103))
	raw := strings.TrimSpace(buf.String())
	// Stable order, and the service marker the ingest pipeline looks for.
	if !strings.HasPrefix(raw, `{"@timestamp":"`) || !strings.Contains(raw, `"service":{"name":"openconsole"`) {
		t.Fatalf("line = %s", raw)
	}
	rec := lines(t, &buf)[0]
	for path, want := range map[string]any{
		"message": "GET /api/auth/me 401", "log.level": "warn", "log.logger": "http",
		"ecs.version": ECSVersion, "service.name": "openconsole", "service.version": "2.16.2",
		"service.environment": "prod", "http.request.method": "GET", "http.request.id": "r1",
		"http.response.status_code": float64(401), "http.response.body.bytes": float64(103),
		"url.path": "/api/auth/me", "source.ip": "10.31.67.52", "user_agent.original": "Firefox",
		"event.duration": float64(509909), "event.kind": "event", "event.outcome": "failure",
		"event.dataset": "openconsole.app",
	} {
		if got := get(rec, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if c, _ := get(rec, "event.category").([]any); len(c) != 1 || c[0] != "web" {
		t.Errorf("event.category = %v", get(rec, "event.category"))
	}
	if ts, _ := rec["@timestamp"].(string); !strings.HasSuffix(ts, "Z") {
		t.Errorf("@timestamp = %v, want UTC", rec["@timestamp"])
	}
	for _, k := range []string{"time", "level", "msg", "method", "status", "client", "log.level"} {
		if _, ok := rec[k]; ok {
			t.Errorf("unexpected top-level key %q", k)
		}
	}
}

func TestECSAuditRecord(t *testing.T) {
	var buf bytes.Buffer
	ecsLogger(&buf).Info("audit", slog.String("event", "pod.exec.denied"), slog.String("user", "bob"),
		slog.String("namespace", "team-a"), slog.String("resource_type", "pod"),
		slog.String("resource_name", "api-1"), slog.String("cluster", "prod"),
		slog.String("container", "app"), slog.Any("error", errors.New("boom")))
	rec := lines(t, &buf)[0]
	for path, want := range map[string]any{
		"message": "bob: pod.exec.denied pod team-a/api-1 on prod", "log.logger": "audit",
		"event.action": "pod.exec.denied", "event.outcome": "failure", "event.kind": "event",
		"event.dataset": "openconsole.audit", "user.name": "bob", "error.message": "boom",
		// The resource acted on: under openconsole.*, never kubernetes.* / container.*.
		"openconsole.namespace": "team-a", "openconsole.container": "app", "openconsole.cluster": "prod",
	} {
		if got := get(rec, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if _, ok := rec["container"]; ok {
		t.Error("container must not be a top-level field")
	}
	if c, _ := get(rec, "event.category").([]any); len(c) != 1 || c[0] != "process" {
		t.Errorf("event.category = %v", get(rec, "event.category"))
	}
}

func TestECSConflictsAndTypes(t *testing.T) {
	var buf bytes.Buffer
	ecsLogger(&buf).Info("startup",
		slog.String("event.action", "x"), slog.String("event", "y"), // both are event.action: last wins
		slog.Duration("took", 1500), slog.Bool("enabled", true), slog.Group("db", slog.String("path", "/data")))
	rec := lines(t, &buf)[0]
	if get(rec, "event.action") != "y" || get(rec, "openconsole.took") != float64(1500) ||
		get(rec, "openconsole.enabled") != true || get(rec, "openconsole.db.path") != "/data" {
		t.Fatalf("record = %v", rec)
	}
	if get(rec, "event.dataset") != "openconsole.app" {
		t.Errorf("event.dataset = %v", get(rec, "event.dataset"))
	}
}

// client-go logs through klog; it must come out as the same JSON stream.
func TestKlogIsRoutedThroughSlog(t *testing.T) {
	var buf bytes.Buffer
	SetDefault(ecsLogger(&buf))
	t.Cleanup(func() { SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))) })

	klog.ErrorS(errors.New("watch closed"), "reflector failed", "resource", "pods")
	klog.Info("plain klog line")
	klog.Flush()

	got := lines(t, &buf)
	if len(got) != 2 {
		t.Fatalf("lines = %d: %s", len(got), buf.String())
	}
	if got[0]["message"] != "reflector failed" || get(got[0], "log.level") != "error" ||
		get(got[0], "error.message") != "watch closed" || get(got[0], "openconsole.resource") != "pods" {
		t.Fatalf("klog error line = %v", got[0])
	}
	if got[1]["message"] != "plain klog line" {
		t.Fatalf("klog info line = %v", got[1])
	}
}
