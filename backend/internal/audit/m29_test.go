package audit

import (
	"context"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

// API_KEY_READ_RETENTION_DAYS alone: only old successful reads made with an
// API key go; the purge repeats every interval and stops with ctx.
func TestRetentionPurgesKeyReadsAndRepeats(t *testing.T) {
	l, st, d := newLogger(t)
	defer d.Close()
	ctx := context.Background()
	old := time.Now().UTC().Add(-48 * time.Hour)
	add := func(name string, ts time.Time, keyID int, verb, outcome string) {
		t.Helper()
		if err := st.AddAuditLog(ctx, models.AuditLog{Timestamp: ts, User: "agent", Action: "pod." + verb,
			Verb: verb, Outcome: outcome, ResourceName: name, APIKeyID: keyID}); err != nil {
			t.Fatal(err)
		}
	}
	names := func() map[string]bool {
		logs, err := st.ListAuditLogsFiltered(ctx, 100, 0, store.AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, e := range logs {
			out[e.ResourceName] = true
		}
		return out
	}
	waitGone := func(name string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for names()[name] {
			if time.Now().After(deadline) {
				t.Fatalf("%s not purged", name)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	add("key-read-old", old, 7, "list", Success)
	add("key-read-new", time.Now().UTC(), 7, "list", Success)
	add("key-read-denied", old, 7, "list", Denied)
	add("key-write-old", old, 7, "delete", Success)
	add("web-read-old", old, 0, "list", Success)

	runCtx, cancel := context.WithCancel(ctx)
	l.StartRetention(runCtx, 0, 1, 20*time.Millisecond)
	waitGone("key-read-old")
	got := names()
	for _, keep := range []string{"key-read-new", "key-read-denied", "key-write-old", "web-read-old"} {
		if !got[keep] {
			t.Fatalf("%s purged; left: %v", keep, got)
		}
	}

	// Later: the next tick purges what has aged since.
	add("key-read-old-2", old, 7, "get", Success)
	waitGone("key-read-old-2")

	// Stopped: nothing is purged any more.
	cancel()
	time.Sleep(60 * time.Millisecond) // a purge in flight finishes
	add("key-read-old-3", old, 7, "logs", Success)
	time.Sleep(100 * time.Millisecond) // five intervals
	if !names()["key-read-old-3"] {
		t.Fatal("purged after ctx was cancelled")
	}
}

// Both settings: everything past LOG_RETENTION_DAYS goes, and key reads go
// sooner. A purge that fails (database gone) only logs.
func TestRetentionBothLimitsAndFailure(t *testing.T) {
	l, st, d := newLogger(t)
	ctx := context.Background()
	for _, e := range []models.AuditLog{
		{Timestamp: time.Now().UTC().Add(-10 * 24 * time.Hour), User: "x", Action: "user.update", Verb: "update", Outcome: Success, ResourceName: "ancient"},
		{Timestamp: time.Now().UTC().Add(-3 * 24 * time.Hour), User: "x", Action: "user.update", Verb: "update", Outcome: Success, ResourceName: "web-3d"},
		{Timestamp: time.Now().UTC().Add(-3 * 24 * time.Hour), User: "x", Action: "pod.list", Verb: "list", Outcome: Success, ResourceName: "key-3d", APIKeyID: 1},
	} {
		if err := st.AddAuditLog(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	l.StartRetention(runCtx, 7, 1, time.Hour)
	deadline := time.Now().Add(3 * time.Second)
	for countAudit(t, st) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("%d entries left, want 1 (web-3d)", countAudit(t, st))
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs, _ := st.ListAuditLogsFiltered(ctx, 10, 0, store.AuditFilter{})
	if logs[0].ResourceName != "web-3d" {
		t.Fatalf("left %q", logs[0].ResourceName)
	}

	_ = d.Close()
	failCtx, stop := context.WithCancel(ctx)
	l.StartRetention(failCtx, 7, 1, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // purges fail and are logged; nothing panics
	stop()
}
