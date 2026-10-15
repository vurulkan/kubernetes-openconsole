package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"k8s-dashboard/backend/internal/logging"
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
// When enabled, every Record() call emits one "audit" line with the event's
// fields, so Elastic / Kibana can filter on them directly from stdout. It is
// the only console line an audited action writes.
func (l *Logger) SetConsoleMirror(enabled bool) {
	l.consoleMirror.Store(enabled)
}

// Record stores one audit event and mirrors it to the console. Action,
// Outcome and the request id are filled in when empty; Cluster is not:
// callers set it to the cluster the action targeted, or leave it empty for
// cluster-independent actions.
func (l *Logger) Record(ctx context.Context, entry models.AuditLog) {
	entry.Timestamp = time.Now().UTC()
	if entry.RequestID == "" {
		entry.RequestID = logging.RequestIDFrom(ctx)
	}
	normalize(&entry)
	if entry.Cluster != "" && entry.ClusterID == 0 {
		entry.ClusterID = l.store.ClusterIDByName(ctx, entry.Cluster)
	}
	_ = l.store.AddAuditLog(ctx, entry)
	if hook := auditMetricHook; hook != nil {
		hook()
	}

	if l.consoleMirror.Load() {
		slog.LogAttrs(ctx, slog.LevelInfo, "audit", consoleAttrs(entry)...)
	}
}

// consoleAttrs are the console fields of an event. Empty values are left out
// so a filter like "has openconsole.cluster" means something. Keys follow
// the ECS mapping in logging/ecs.go: event → event.action, user →
// user.name, remote_ip → source.ip, user_agent → user_agent.original,
// request_id → http.request.id, error → error.message; the rest go under
// openconsole.*.
func consoleAttrs(e models.AuditLog) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("event", e.Action),
		slog.String("verb", e.Verb),
		slog.String("outcome", e.Outcome),
	}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	add("reason", e.Reason)
	add("user", e.User)
	add("auth_source", e.AuthSource)
	add("cluster", e.Cluster)
	if e.ClusterID > 0 {
		attrs = append(attrs, slog.Int("cluster_id", e.ClusterID))
	}
	add("namespace", e.Namespace)
	add("resource_type", e.ResourceType)
	add("resource_name", e.ResourceName)
	add("request_id", e.RequestID)
	add("remote_ip", e.SourceIP)
	add("user_agent", e.UserAgent)
	attrs = append(attrs, detailAttrs(e.Details)...)
	return attrs
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
