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
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{ReplaceAttr: ecsReplaceAttr})
	return slog.New(h).With(slog.String("ecs.version", ECSVersion), slog.String("service", "openconsole"),
		slog.String("version", "2.16.1"), slog.String("env", "prod"))
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

func TestECSFieldNames(t *testing.T) {
	var buf bytes.Buffer
	l := ecsLogger(&buf)
	l.Info("http.request",
		slog.String("method", "GET"), slog.String("path", "/api/x"), slog.Int("status", 403),
		slog.Int64("duration_ms", 12), slog.String("remote_ip", "10.0.0.5"),
		slog.String("request_id", "r1"), slog.String("user_agent", "curl/8"), slog.String("trace_id", "abc"))
	l.Warn("audit", slog.String("event", "pod.exec.denied"), slog.String("user", "bob"),
		slog.String("namespace", "team-a"), slog.String("container", "app"), slog.Any("error", errors.New("boom")))

	got := lines(t, &buf)
	req, audit := got[0], got[1]
	want := map[string]any{
		"message": "http.request", "log.level": "info", "ecs.version": ECSVersion,
		"service.name": "openconsole", "service.version": "2.16.1", "service.environment": "prod",
		"http.request.method": "GET", "url.path": "/api/x", "http.response.status_code": float64(403),
		"event.duration": float64(12_000_000), "client.ip": "10.0.0.5", "http.request.id": "r1",
		"user_agent.original": "curl/8", "trace.id": "abc",
	}
	for k, v := range want {
		if req[k] != v {
			t.Errorf("%s = %v, want %v", k, req[k], v)
		}
	}
	if ts, _ := req["@timestamp"].(string); !strings.HasSuffix(ts, "Z") {
		t.Errorf("@timestamp = %v, want UTC", req["@timestamp"])
	}
	for _, k := range []string{"time", "level", "msg", "method", "status", "user_agent"} {
		if _, ok := req[k]; ok {
			t.Errorf("raw key %q left in ECS output", k)
		}
	}
	// The resource acted on lives under openconsole.*, never in kubernetes.* /
	// container.* which belong to the shipper's metadata.
	for k, v := range map[string]any{
		"log.level": "warn", "event.action": "pod.exec.denied", "user.name": "bob",
		"openconsole.namespace": "team-a", "openconsole.container": "app", "error.message": "boom",
	} {
		if audit[k] != v {
			t.Errorf("audit %s = %v, want %v", k, audit[k], v)
		}
	}
	if _, ok := audit["container"]; ok {
		t.Error("container must not be a top-level string")
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
	if got[0]["message"] != "reflector failed" || got[0]["log.level"] != "error" || got[0]["error.message"] != "watch closed" {
		t.Fatalf("klog error line = %v", got[0])
	}
	t.Log(buf.String())
	if got[1]["message"] != "plain klog line" {
		t.Fatalf("klog info line = %v", got[1])
	}
}
