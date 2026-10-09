package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestSetupDisabledWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := Setup(context.Background(), "1.0.0", "test")
	if err != nil || Enabled {
		t.Fatalf("Setup = %v, enabled=%v", err, Enabled)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestSetupExportsOverOTLP points the exporter at a fake collector and
// checks a span arrives on POST /v1/traces carrying the service resource.
func TestSetupExportsOverOTLP(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.Method+" "+r.URL.Path+" "+string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_SERVICE_NAME", "oc-test")
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		Enabled = false
	})

	shutdown, err := Setup(context.Background(), "9.9.9", "ci")
	if err != nil || !Enabled {
		t.Fatalf("Setup = %v, enabled=%v", err, Enabled)
	}
	_, span := otel.Tracer("test").Start(context.Background(), "unit-span")
	span.End()
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("collector received nothing")
	}
	got := strings.Join(bodies, "\n")
	for _, want := range []string{"POST /v1/traces", "unit-span", "oc-test", "9.9.9", "ci"} {
		if !strings.Contains(got, want) {
			t.Errorf("export missing %q", want)
		}
	}
}
