// Package logging provides structured logging via log/slog with env-driven
// format and level selection. Prefer slog.Info/Warn/... everywhere; this
// package only initializes the default handler.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config describes the logger configuration sourced from env vars.
type Config struct {
	Level        string // debug|info|warn|error (default: info)
	Format       string // json|text (default: text)
	Output       string // stdout|stderr (default: stdout)
	AddSource    bool   // include source file:line
	Service      string // static attribute, e.g. "openconsole"
	Version      string // static attribute, build version
	Env          string // deployment env (dev|prod|...)
	IncludeAudit bool   // mirror audit records to the console
}

// New constructs a *slog.Logger from cfg. The returned logger carries fixed
// service/version/env attributes so every record is self-describing in Elastic.
func New(cfg Config) *slog.Logger {
	level := parseLevel(cfg.Level)
	writer := pickWriter(cfg.Output)

	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		handler = slog.NewJSONHandler(writer, handlerOpts)
	default:
		handler = slog.NewTextHandler(writer, handlerOpts)
	}

	attrs := make([]slog.Attr, 0, 3)
	if cfg.Service != "" {
		attrs = append(attrs, slog.String("service", cfg.Service))
	}
	if cfg.Version != "" {
		attrs = append(attrs, slog.String("version", cfg.Version))
	}
	if cfg.Env != "" {
		attrs = append(attrs, slog.String("env", cfg.Env))
	}
	if len(attrs) > 0 {
		handler = handler.WithAttrs(attrs)
	}

	return slog.New(handler)
}

// SetDefault wires the logger into the slog default so bare slog.Info etc. work.
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}

func parseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func pickWriter(out string) io.Writer {
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "stderr":
		return os.Stderr
	default:
		return os.Stdout
	}
}

// Sensitive keys that must never be logged verbatim.
var sensitiveKeys = map[string]struct{}{
	"password":          {},
	"bindpassword":      {},
	"clientsecret":      {},
	"token":             {},
	"authtoken":         {},
	"authorization":     {},
	"kubeconfig":        {},
	"kubeconfigbase64":  {},
	"cacertbase64":      {},
	"secret":            {},
}

// Redact returns a safe copy of a key/value map, replacing sensitive values.
// Call it before logging arbitrary request payloads.
func Redact(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if _, hit := sensitiveKeys[strings.ToLower(k)]; hit {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

// ContextKey is the context key used to carry a request id through handlers.
type ContextKey string

const RequestIDKey ContextKey = "request_id"

// RequestIDFrom returns the request id from ctx or empty string.
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}
