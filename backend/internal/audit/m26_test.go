package audit

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

func newLogger(t *testing.T) (*Logger, *store.Store, *db.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(d.Conn)
	if err != nil {
		t.Fatal(err)
	}
	return New(st), st, d
}

func countAudit(t *testing.T, st *store.Store) int {
	t.Helper()
	n, err := st.CountAuditLogsFiltered(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// LOG_RETENTION_DAYS=0 keeps everything (it used to mean 30); a positive
// value purges right at start, not only 12 hours later.
func TestRetentionZeroKeepsAndPositivePurgesAtStart(t *testing.T) {
	l, st, d := newLogger(t)
	defer d.Close()
	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := st.AddAuditLog(context.Background(), models.AuditLog{Timestamp: old, User: "x", Action: "pod.list", Verb: "list", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.StartRetention(ctx, 0, 0, time.Hour)
	time.Sleep(100 * time.Millisecond)
	if countAudit(t, st) != 1 {
		t.Fatal("retention 0 purged")
	}
	l.StartRetention(ctx, 1, 0, time.Hour)
	deadline := time.Now().Add(2 * time.Second)
	for countAudit(t, st) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("retention 1 did not purge at start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An audit event the database refuses is counted and logged, not dropped
// silently; Wait waits for events started with Go.
func TestAuditWriteFailureIsCounted(t *testing.T) {
	l, _, d := newLogger(t)
	var failed, ok atomic.Int64
	SetFailureHook(func() { failed.Add(1) })
	SetMetricHook(func() { ok.Add(1) })
	t.Cleanup(func() { SetFailureHook(nil); SetMetricHook(nil) })

	l.RecordAsync(models.AuditLog{User: "x", Action: "pod.list", Verb: "list"})
	l.Wait(context.Background())
	if ok.Load() != 1 {
		t.Fatalf("written: %d, want 1 (Wait returned before the write)", ok.Load())
	}
	d.Close()
	l.Record(context.Background(), models.AuditLog{User: "x", Action: "pod.list", Verb: "list"})
	if failed.Load() != 1 {
		t.Fatalf("failures counted: %d, want 1", failed.Load())
	}
}
