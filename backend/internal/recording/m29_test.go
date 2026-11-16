package recording

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

// newM29Manager is newTestManager plus the database, so a test can backdate rows.
func newM29Manager(t *testing.T, settings models.RecordingSettings) (*Manager, *sql.DB) {
	t.Helper()
	tmp := t.TempDir()
	database, err := db.Open(filepath.Join(tmp, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAfterPendingWrites(database.Conn) })
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(context.Background(), st, audit.New(st), filepath.Join(tmp, "recordings"), settings)
	if err != nil {
		t.Fatal(err)
	}
	return m, database.Conn
}

// finished records one session of about size bytes and closes it.
func finished(t *testing.T, m *Manager, size int) *Session {
	t.Helper()
	s := live(t, m, size)
	s.Close()
	return s
}

// live starts a session, writes about size bytes and leaves it open.
func live(t *testing.T, m *Manager, size int) *Session {
	t.Helper()
	s, err := m.Start(context.Background(), Meta{User: "u", Namespace: "ns", Pod: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if size > 0 {
		s.Write([]byte(strings.Repeat("y", size)))
	}
	return s
}

func exists(t *testing.T, m *Manager, s *Session) bool {
	t.Helper()
	_, rowErr := m.Get(context.Background(), s.rowID)
	_, fileErr := os.Stat(s.path)
	switch {
	case rowErr == nil && fileErr == nil:
		return true
	case errors.Is(rowErr, ErrNotFound) && os.IsNotExist(fileErr):
		return false
	}
	t.Fatalf("recording %s half removed: row err %v, file err %v", s.sessionID, rowErr, fileErr)
	return false
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// fakeDisk is a volume of capacity bytes on which the .cast files in dir are
// the only thing that changes: deleting a recording frees its bytes.
type fakeDisk struct {
	dir      string
	capacity atomic.Int64
}

func (d *fakeDisk) free(string) (uint64, bool) {
	entries, _ := os.ReadDir(d.dir)
	used := int64(0)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), fileExt) {
			used += info.Size()
		}
	}
	if f := d.capacity.Load() - used; f > 0 {
		return uint64(f), true
	}
	return 0, true
}

func auditByVerb(t *testing.T, m *Manager, verb string) []models.AuditLog {
	t.Helper()
	m.audit.Wait(context.Background())
	logs, err := m.store.ListAuditLogsFiltered(context.Background(), 100, 0, store.AuditFilter{Verb: verb})
	if err != nil {
		t.Fatal(err)
	}
	return logs
}

// Low disk: the oldest recordings go until the free-space floor holds again,
// and no more.
func TestLowDiskEvictsOnlyWhatIsNeeded(t *testing.T) {
	settings := defaults()
	settings.MinFreeMB = 1 // with the 1 MB reserve, a new session needs 2 MB free
	m, _ := newM29Manager(t, settings)
	first, second, third := finished(t, m, 600<<10), finished(t, m, 600<<10), finished(t, m, 600<<10)
	disk := &fakeDisk{dir: m.dir}
	all := fileSize(t, first.path) + fileSize(t, second.path) + fileSize(t, third.path)
	disk.capacity.Store(2*mb + all - fileSize(t, first.path)/2) // removing first is enough
	m.freeSpace = disk.free

	if u, err := m.Usage(context.Background()); err != nil || !u.LimitReached || u.FreeBytes >= 2*mb {
		t.Fatalf("usage before = %+v, %v", u, err)
	}
	if err := m.ensureSpace(context.Background(), mb); err != nil {
		t.Fatalf("ensureSpace = %v", err)
	}
	if exists(t, m, first) || !exists(t, m, second) || !exists(t, m, third) {
		t.Fatalf("want only the oldest evicted: first %v second %v third %v",
			exists(t, m, first), exists(t, m, second), exists(t, m, third))
	}
	ev := auditByVerb(t, m, audit.VerbEvict)
	if len(ev) != 1 || ev[0].Reason != "low_disk" || ev[0].ResourceName != first.sessionID {
		t.Fatalf("evict audit = %+v", ev)
	}
}

// Low disk that deleting every recording would not fix (the database or
// something else on the volume filled it): keep the recordings and refuse,
// instead of deleting all of them and refusing anyway.
func TestLowDiskEvictionThatCannotHelpKeepsRecordings(t *testing.T) {
	settings := defaults()
	settings.MinFreeMB = 1
	m, _ := newM29Manager(t, settings)
	recs := []*Session{finished(t, m, 300<<10), finished(t, m, 300<<10), finished(t, m, 300<<10)}
	disk := &fakeDisk{dir: m.dir}
	all := int64(0)
	for _, s := range recs {
		all += fileSize(t, s.path)
	}
	disk.capacity.Store(all + mb) // even with every recording gone: 1 MB free, 2 MB needed
	m.freeSpace = disk.free

	if err := m.ensureSpace(context.Background(), mb); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("ensureSpace = %v, want ErrNoSpace", err)
	}
	for i, s := range recs {
		if !exists(t, m, s) {
			t.Fatalf("recording %d deleted although deleting all of them could not make room", i)
		}
	}
	if ev := auditByVerb(t, m, audit.VerbEvict); len(ev) != 0 {
		t.Fatalf("evict audit = %+v", ev)
	}
}

// Over quota because of sessions still recording: evicting finished
// recordings can't bring it under, so they stay.
func TestQuotaHeldByLiveSessionsKeepsRecordings(t *testing.T) {
	settings := defaults()
	settings.MaxTotalMB = 2 // 1 MB per session
	m, _ := newM29Manager(t, settings)
	old := finished(t, m, 100<<10)
	a := live(t, m, 800<<10)
	b := live(t, m, 800<<10) // 0.1 + 0.8 + 1 MB reserve ≤ 2 MB
	defer a.Close()
	defer b.Close()

	if _, err := m.Start(context.Background(), Meta{User: "u"}); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("Start = %v, want ErrNoSpace (1.6 MB live + 1 MB reserve > 2 MB)", err)
	}
	if !exists(t, m, old) {
		t.Fatal("finished recording evicted although the live sessions alone exceed the quota")
	}
}

// guardLoop stops live recordings when the disk can't hold them, and leaves
// finished recordings alone when evicting them would not help.
func TestGuardLoopStopsLiveRecordingsOnLowDisk(t *testing.T) {
	settings := defaults()
	settings.MinFreeMB = 1
	m, _ := newM29Manager(t, settings)
	old := finished(t, m, 100<<10)
	s := live(t, m, 10)
	m.freeSpace = func(string) (uint64, bool) { return 0, true } // something else filled the volume
	m.guardEvery = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.guardLoop(ctx); close(done) }()
	waitUntil(t, "the live recording to stop", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.stopped
	})
	cancel()
	<-done
	res := s.Close()
	if !res.Truncated || res.TruncateReason != ReasonDiskQuota {
		t.Fatalf("result = %+v", res)
	}
	if !exists(t, m, old) {
		t.Fatal("finished recording deleted although it could not make room")
	}
}

// With room to make, guardLoop evicts the oldest finished recording and the
// live one keeps recording; with no live session it does nothing at all.
func TestGuardLoopEvictsForLiveSessions(t *testing.T) {
	settings := defaults()
	settings.MinFreeMB = 1
	m, _ := newM29Manager(t, settings)
	old, newer := finished(t, m, 400<<10), finished(t, m, 400<<10)
	disk := &fakeDisk{dir: m.dir}
	short := mb + fileSize(t, old.path) + fileSize(t, newer.path) - 1 // 1 byte under the floor
	disk.capacity.Store(short)
	m.freeSpace = disk.free
	m.guardEvery = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.guardLoop(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond) // ten ticks without a live session
	if !exists(t, m, old) {
		t.Fatal("guardLoop evicted with no live session")
	}

	disk.capacity.Store(short + 10*mb) // room for Start
	s, err := m.Start(context.Background(), Meta{User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	disk.capacity.Store(short) // the volume fills again while the session runs
	waitUntil(t, "the guard to evict", func() bool {
		_, err := m.Get(context.Background(), old.rowID)
		return errors.Is(err, ErrNotFound)
	})
	cancel()
	<-done
	if !exists(t, m, newer) {
		t.Fatal("guard evicted more than needed")
	}
	if res := s.Close(); res.Truncated {
		t.Fatalf("live recording stopped although eviction made room: %+v", res)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Retention drops finished recordings started before the cutoff (also rows
// whose file is already gone), keeps newer ones and sessions still open, and
// audits one purge event.
func TestRetentionPurge(t *testing.T) {
	settings := defaults()
	settings.RetentionDays = 7
	m, conn := newM29Manager(t, settings)
	ctx := context.Background()
	backdate := func(s *Session) {
		if _, err := conn.Exec(`UPDATE session_recordings SET started_at = ? WHERE id = ?`,
			time.Now().UTC().Add(-10*24*time.Hour), s.rowID); err != nil {
			t.Fatal(err)
		}
	}
	old, oldNoFile, recent := finished(t, m, 1000), finished(t, m, 1000), finished(t, m, 1000)
	oldLive := live(t, m, 10)
	defer oldLive.Close()
	for _, s := range []*Session{old, oldNoFile, oldLive} {
		backdate(s)
	}
	if err := os.Remove(oldNoFile.path); err != nil {
		t.Fatal(err)
	}
	oldSize := fileSize(t, old.path)
	rec, _ := m.Get(ctx, oldNoFile.rowID)
	freed := oldSize + rec.SizeBytes

	m.purge(ctx)
	if exists(t, m, old) {
		t.Fatal("recording past retention kept")
	}
	if _, err := m.Get(ctx, oldNoFile.rowID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("row without a file kept: %v", err)
	}
	if !exists(t, m, recent) || !exists(t, m, oldLive) {
		t.Fatal("purge removed a recent or still-open recording")
	}
	ev := auditByVerb(t, m, audit.VerbPurge)
	if len(ev) != 1 || ev[0].User != "system" ||
		fmt.Sprint(ev[0].Details["count"]) != "2" ||
		fmt.Sprint(ev[0].Details["retention_days"]) != "7" ||
		fmt.Sprint(ev[0].Details["size_bytes"]) != fmt.Sprint(freed) {
		t.Fatalf("purge audit = %+v (want count 2, size %d)", ev, freed)
	}

	// Retention 0 keeps everything.
	settings.RetentionDays = 0
	if _, err := m.UpdateSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	backdate(recent)
	m.purge(ctx)
	if !exists(t, m, recent) {
		t.Fatal("retention 0 purged")
	}
}

// The orphan sweep removes only old .cast files with no row: not a file of
// a known recording, not a file just created (its row may be on its way),
// not other files or directories, and nothing when the directory is unusable.
func TestSweepOrphans(t *testing.T) {
	m, _ := newM29Manager(t, defaults())
	known := finished(t, m, 100)
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	write := func(name string) string {
		p := filepath.Join(m.dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		return p
	}
	orphan := write("0000-orphan" + fileExt)
	young := write("0001-young" + fileExt)
	other := write("notes.txt")
	dir := filepath.Join(m.dir, "sub"+fileExt)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{known.path, orphan, other, dir} {
		if err := os.Chtimes(p, twoHoursAgo, twoHoursAgo); err != nil {
			t.Fatal(err)
		}
	}

	m.dirErr = errors.New("not writable")
	m.sweepOrphans(context.Background())
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("swept an unusable directory")
	}
	m.dirErr = nil

	m.sweepOrphans(context.Background())
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("old orphan file kept")
	}
	for _, p := range []string{known.path, young, other, dir} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", filepath.Base(p), err)
		}
	}
	if !exists(t, m, known) {
		t.Fatal("known recording removed")
	}
}
