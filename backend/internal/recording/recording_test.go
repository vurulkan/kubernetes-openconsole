package recording

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

func newTestManager(t *testing.T, settings models.RecordingSettings) *Manager {
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
	return m
}

func defaults() models.RecordingSettings {
	return models.RecordingSettings{Enabled: true, RetentionDays: 30, MaxSessionMB: 1, MaxTotalMB: 100,
		MinFreeMB: 0, DiskPolicy: models.RecordingPolicyEvictOldest}
}

// readCast parses a cast file into its header and events.
func readCast(t *testing.T, path string) (map[string]any, [][]any) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	var header map[string]any
	var events [][]any
	for i := 0; sc.Scan(); i++ {
		if i == 0 {
			if err := json.Unmarshal(sc.Bytes(), &header); err != nil {
				t.Fatalf("header: %v", err)
			}
			continue
		}
		var ev []any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("event %d: %v (%q)", i, err, sc.Text())
		}
		events = append(events, ev)
	}
	return header, events
}

func TestSessionWritesCastV2(t *testing.T) {
	m := newTestManager(t, defaults())
	s, err := m.Start(context.Background(), Meta{User: "alice", Namespace: "ns", Pod: "p"})
	if err != nil {
		t.Fatal(err)
	}
	s.Resize(120, 40) // before any output → header dimensions
	ş := []byte("ş")
	s.Write([]byte("hello "))
	s.Write(ş[:1]) // split multi-byte rune across chunks
	s.Write(append(ş[1:], '\n'))
	s.Resize(100, 30)
	res := s.Close()

	header, events := readCast(t, s.path)
	if header["version"].(float64) != 2 || header["width"].(float64) != 120 || header["height"].(float64) != 40 {
		t.Fatalf("bad header: %v", header)
	}
	var out strings.Builder
	var sawResize bool
	for _, ev := range events {
		switch ev[1] {
		case "o":
			out.WriteString(ev[2].(string))
		case "r":
			sawResize = ev[2] == "100x30"
		}
	}
	if out.String() != "hello ş\n" {
		t.Fatalf("output = %q", out.String())
	}
	if !sawResize {
		t.Fatal("missing resize event")
	}
	if res.Truncated || res.SizeBytes == 0 {
		t.Fatalf("result = %+v", res)
	}
	rec, err := m.Get(context.Background(), s.rowID)
	if err != nil || rec.EndedAt == nil || rec.SizeBytes != res.SizeBytes {
		t.Fatalf("row = %+v err=%v", rec, err)
	}
}

func TestSessionSizeCapTruncates(t *testing.T) {
	m := newTestManager(t, defaults()) // 1 MB per session
	s, err := m.Start(context.Background(), Meta{User: "bob", Namespace: "ns", Pod: "p"})
	if err != nil {
		t.Fatal(err)
	}
	chunk := []byte(strings.Repeat("x", 64*1024))
	for i := 0; i < 40; i++ {
		s.Write(chunk)
	}
	res := s.Close()
	if !res.Truncated || res.TruncateReason != ReasonSizeLimit {
		t.Fatalf("expected truncation, got %+v", res)
	}
	if res.SizeBytes > mb+1024 {
		t.Fatalf("size %d exceeds cap", res.SizeBytes)
	}
	_, events := readCast(t, s.path)
	last := events[len(events)-1][2].(string)
	if !strings.Contains(last, "recording stopped") {
		t.Fatalf("missing truncation marker: %q", last)
	}
}

func TestQuotaEvictsOldest(t *testing.T) {
	settings := defaults()
	settings.MaxTotalMB = 2 // room for one finished ~1 MB recording + 1 MB reserve
	m := newTestManager(t, settings)
	ctx := context.Background()
	fill := func() *Session {
		s, err := m.Start(ctx, Meta{User: "u", Namespace: "ns", Pod: "p"})
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte(strings.Repeat("y", 700*1024)))
		s.Close()
		return s
	}
	first := fill()
	second := fill() // 0.7 MB used + 1 MB reserve fits in 2 MB → no eviction
	if _, err := m.Get(ctx, first.rowID); err != nil {
		t.Fatalf("first recording evicted too early: %v", err)
	}
	fill() // 1.4 MB used + 1 MB reserve > 2 MB → evict the oldest
	if _, err := m.Get(ctx, first.rowID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest recording should be evicted, got %v", err)
	}
	if _, err := os.Stat(first.path); !os.IsNotExist(err) {
		t.Fatal("evicted file still on disk")
	}
	if _, err := m.Get(ctx, second.rowID); err != nil {
		t.Fatalf("second recording should survive: %v", err)
	}

	// Same pressure under the stop policy: refuse instead of evicting.
	settings.DiskPolicy = models.RecordingPolicyStop
	if _, err := m.UpdateSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(ctx, Meta{User: "u", Namespace: "ns", Pod: "p"}); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("stop policy should refuse, got %v", err)
	}
	if _, err := m.Get(ctx, second.rowID); err != nil {
		t.Fatalf("stop policy must not evict: %v", err)
	}
}

func TestDisabledAndValidation(t *testing.T) {
	settings := defaults()
	settings.Enabled = false
	m := newTestManager(t, settings)
	if _, err := m.Start(context.Background(), Meta{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
	bad := defaults()
	bad.DiskPolicy = "yolo"
	if _, err := m.UpdateSettings(context.Background(), bad); err == nil {
		t.Fatal("expected validation error")
	}
	var nilSession *Session
	nilSession.Write([]byte("x")) // must not panic
	nilSession.Close()
}

// closeAfterPendingWrites: see the copy in internal/api — eviction audits are
// written from goroutines and must finish before the temp dir is removed.
func closeAfterPendingWrites(db *sql.DB) {
	conn, err := db.Conn(context.Background())
	_ = db.Close()
	if err == nil {
		_ = conn.Close()
	}
}
