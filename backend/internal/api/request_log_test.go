package api

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Successful probe and metrics requests are logged at debug level only;
// everything else, and failing probes, at info or above.
func TestRequestLogLevels(t *testing.T) {
	e := newTestEnv(t)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, p := range []string{"/healthz", "/livez", "/readyz", "/metrics"} {
		e.do("GET", p, "", nil)
	}
	e.do("GET", "/api/namespaces", "", nil) // 401

	out := buf.String()
	for _, p := range []string{`"path":"/healthz"`, `"path":"/livez"`, `"path":"/readyz"`, `"path":"/metrics"`} {
		if strings.Contains(out, p) {
			t.Errorf("%s logged at info: %s", p, out)
		}
	}
	if !strings.Contains(out, `"path":"/api/namespaces"`) || !strings.Contains(out, `"status":401`) {
		t.Fatalf("API request not logged: %s", out)
	}
}
