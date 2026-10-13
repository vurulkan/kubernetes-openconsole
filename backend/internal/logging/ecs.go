package logging

import (
	"log/slog"
	"strings"
	"time"
)

// ECSVersion is the Elastic Common Schema version the "ecs" format follows.
const ECSVersion = "8.11.0"

// ecsFieldNames maps the attribute keys used across the code base to their
// ECS field. Keys not listed here go under "openconsole.<key>", so they can
// never collide with ECS objects or with the kubernetes.* / container.*
// metadata a shipper adds (the namespace / pod / container in our records
// are the ones acted on, not the pod that wrote the log line).
var ecsFieldNames = map[string]string{
	"service":    "service.name",
	"version":    "service.version",
	"env":        "service.environment",
	"user":       "user.name",
	"user_agent": "user_agent.original",
	"error":      "error.message",
	"err":        "error.message", // klog / logr
	"event":      "event.action",
	"method":     "http.request.method",
	"status":     "http.response.status_code",
	"path":       "url.path",
	"remote_ip":  "client.ip",
	"request_id": "http.request.id",
	"trace_id":   "trace.id",
}

// ecsReplaceAttr renames slog's built-in and our own top-level keys to ECS.
// Keys that already contain a dot are taken as deliberate ECS / namespaced
// names and kept.
func ecsReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if t, ok := a.Value.Any().(time.Time); ok {
			return slog.String("@timestamp", t.UTC().Format("2006-01-02T15:04:05.000000Z"))
		}
		return slog.Attr{Key: "@timestamp", Value: a.Value}
	case slog.LevelKey:
		if l, ok := a.Value.Any().(slog.Level); ok {
			return slog.String("log.level", strings.ToLower(l.String()))
		}
		return slog.String("log.level", strings.ToLower(a.Value.String()))
	case slog.MessageKey:
		return slog.Attr{Key: "message", Value: a.Value}
	case slog.SourceKey:
		if src, ok := a.Value.Any().(*slog.Source); ok && src != nil {
			return slog.Group("log.origin",
				slog.String("function", src.Function),
				slog.Group("file", slog.String("name", src.File), slog.Int("line", src.Line)),
			)
		}
		return slog.Attr{Key: "log.origin", Value: a.Value}
	case "duration_ms":
		// ECS event.duration is in nanoseconds.
		if a.Value.Kind() == slog.KindInt64 {
			return slog.Int64("event.duration", a.Value.Int64()*int64(time.Millisecond))
		}
	}
	if strings.Contains(a.Key, ".") {
		return a
	}
	if name, ok := ecsFieldNames[a.Key]; ok {
		return slog.Attr{Key: name, Value: a.Value}
	}
	return slog.Attr{Key: "openconsole." + a.Key, Value: a.Value}
}
