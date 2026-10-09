package api

import (
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestRequestSpans checks each API request gets one server span named after
// its route pattern, tagged with the user and cluster, and that probes are
// not traced.
func TestRequestSpans(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })

	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("GET", "/api/namespaces/team-a/pods", admin, nil, http.StatusOK)
	e.do("GET", "/healthz", "", nil)

	var found bool
	for _, s := range rec.Ended() {
		if s.Name() == "GET /healthz" {
			t.Errorf("unexpected span %q", s.Name())
		}
		if s.Name() != "GET /api/namespaces/{namespace}/pods" {
			continue
		}
		found = true
		attrs := map[string]string{}
		for _, a := range s.Attributes() {
			attrs[string(a.Key)] = a.Value.Emit()
		}
		if attrs["enduser.id"] != "root" || attrs["openconsole.cluster"] != "alpha" || attrs["openconsole.request_id"] == "" {
			t.Errorf("span attributes = %v", attrs)
		}
	}
	if !found {
		names := []string{}
		for _, s := range rec.Ended() {
			names = append(names, s.Name())
		}
		t.Fatalf("no route-named span; got %v", names)
	}
}
