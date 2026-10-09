// Package telemetry wires OpenTelemetry tracing. It is off unless an OTLP
// endpoint is configured with the standard env vars
// (OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT), so a
// default install pays nothing. Spans are exported over OTLP/HTTP; the
// sampler, headers, timeout etc. follow the standard OTEL_* variables.
package telemetry

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Enabled reports whether tracing was set up.
var Enabled bool

// Configured reports whether the environment asks for tracing.
func Configured() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Setup installs the global tracer provider and W3C trace-context
// propagation. The returned func flushes and stops it (call on shutdown).
func Setup(ctx context.Context, version, env string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if !Configured() {
		return noop, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, err
	}
	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "openconsole"
	}
	attrs := []resource.Option{resource.WithAttributes(semconv.ServiceName(serviceName))}
	if version != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceVersion(version)))
	}
	if env != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.DeploymentEnvironment(env)))
	}
	attrs = append(attrs, resource.WithFromEnv(), resource.WithHost())
	res, err := resource.New(ctx, attrs...)
	if err != nil {
		return noop, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	Enabled = true
	slog.Info("tracing enabled", slog.String("service", serviceName))
	return tp.Shutdown, nil
}
