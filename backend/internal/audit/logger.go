package audit

import (
	"context"
	"time"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

type Logger struct {
	store *store.Store
}

func New(store *store.Store) *Logger {
	return &Logger{store: store}
}

func (l *Logger) Record(ctx context.Context, entry models.AuditLog) {
	entry.Timestamp = time.Now().UTC()
	_ = l.store.AddAuditLog(ctx, entry)
}

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
