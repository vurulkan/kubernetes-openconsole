package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

type Logger struct {
	store         *store.Store
	consoleMirror atomic.Bool
}

func New(store *store.Store) *Logger {
	return &Logger{store: store}
}

// SetConsoleMirror toggles mirroring audit events to the default slog logger.
// When enabled, every Record() call emits an "audit" event with the same fields
// so Elastic/Kibana can consume them directly from stdout.
func (l *Logger) SetConsoleMirror(enabled bool) {
	l.consoleMirror.Store(enabled)
}

func (l *Logger) Record(ctx context.Context, entry models.AuditLog) {
	entry.Timestamp = time.Now().UTC()
	_ = l.store.AddAuditLog(ctx, entry)
	if hook := auditMetricHook; hook != nil {
		hook()
	}

	if l.consoleMirror.Load() {
		slog.LogAttrs(ctx, slog.LevelInfo, "audit",
			slog.String("event", entry.Action),
			slog.String("user", entry.User),
			slog.String("namespace", entry.Namespace),
			slog.String("resource_type", entry.ResourceType),
			slog.String("resource_name", entry.ResourceName),
			slog.Time("ts", entry.Timestamp),
		)
	}
}

// auditMetricHook, if set, is invoked on every Record() so an outer package
// can increment a counter without the audit package depending on it.
var auditMetricHook func()

// SetMetricHook installs the counter callback.
func SetMetricHook(h func()) { auditMetricHook = h }

func (l *Logger) StartRetention(ctx context.Context, retentionDays int, interval time.Duration) {
	if retentionDays <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
				_ = l.store.PurgeAuditLogs(context.Background(), cutoff)
			}
		}
	}()
}
