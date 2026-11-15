package audit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

type Logger struct {
	store         *store.Store
	consoleMirror atomic.Bool
	pending       sync.WaitGroup
}

// Go runs f (which records an event) in the background; Wait waits for it.
func (l *Logger) Go(f func()) {
	l.pending.Add(1)
	go func() {
		defer l.pending.Done()
		f()
	}()
}

// RecordAsync records e in the background (see Go).
func (l *Logger) RecordAsync(e models.AuditLog) {
	l.Go(func() { l.Record(context.Background(), e) })
}

// Wait blocks until every event started with Go is written, or ctx ends.
// Called on shutdown, before the database is closed.
func (l *Logger) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { l.pending.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("audit: shutdown before every event was written")
	}
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
	if err := l.store.AddAuditLog(ctx, entry); err != nil {
		// The console line below still carries the event, when mirroring is on.
		slog.Error("audit write failed", slog.String("event", entry.Action), slog.String("user", entry.User),
			slog.String("request_id", entry.RequestID), slog.Any("error", err))
		if hook := auditFailureHook; hook != nil {
			hook()
		}
	} else if hook := auditMetricHook; hook != nil {
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
	if e.APIKeyID > 0 {
		attrs = append(attrs, slog.Int("api_key_id", e.APIKeyID))
	}
	add("api_key_name", e.APIKeyName)
	attrs = append(attrs, detailAttrs(e.Details)...)
	return attrs
}

// auditMetricHook, if set, is invoked on every Record() so an outer package
// can increment a counter without the audit package depending on it.
var auditMetricHook func()

// SetMetricHook installs the counter callback.
func SetMetricHook(h func()) { auditMetricHook = h }

// auditFailureHook, if set, is invoked when an event could not be stored.
var auditFailureHook func()

// SetFailureHook installs the write-failure counter callback.
func SetFailureHook(h func()) { auditFailureHook = h }

// StartRetention purges audit entries older than retentionDays (0 = keep
// everything), and successful API key reads older than keyReadDays (they are
// by far the largest share: an agent reads a lot). It purges once right away,
// so a pod that restarts more often than interval still purges, then every
// interval.
func (l *Logger) StartRetention(ctx context.Context, retentionDays, keyReadDays int, interval time.Duration) {
	if retentionDays <= 0 && keyReadDays <= 0 {
		return
	}
	purge := func() {
		now := time.Now().UTC()
		if retentionDays > 0 {
			if err := l.store.PurgeAuditLogs(ctx, now.Add(-time.Duration(retentionDays)*24*time.Hour)); err != nil {
				slog.Warn("audit purge failed", slog.Any("error", err))
			}
		}
		if keyReadDays > 0 {
			if err := l.store.PurgeAPIKeyReads(ctx, now.Add(-time.Duration(keyReadDays)*24*time.Hour)); err != nil {
				slog.Warn("audit purge (API key reads) failed", slog.Any("error", err))
			}
		}
	}
	go func() {
		purge()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				purge()
			}
		}
	}()
}
