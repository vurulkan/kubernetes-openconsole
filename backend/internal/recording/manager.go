// Package recording captures pod exec sessions as asciicast v2 files
// (https://docs.asciinema.org/manual/asciicast/v2/) and owns their lifecycle:
// settings, disk quota / eviction, retention and startup recovery.
package recording

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

var (
	// ErrDisabled means recording is switched off in settings.
	ErrDisabled = errors.New("session recording disabled")
	// ErrNoSpace means the quota / free-space floor could not be satisfied
	// (stop policy, or nothing left to evict).
	ErrNoSpace = errors.New("recording disk quota reached")
	// ErrActive is returned when deleting a recording whose session is live.
	ErrActive = errors.New("recording is still in progress")
	// ErrNotFound is returned for an unknown recording id.
	ErrNotFound = errors.New("recording not found")
)

const (
	mb = int64(1024 * 1024)

	guardInterval     = 30 * time.Second
	retentionInterval = 24 * time.Hour
	retentionDelay    = time.Minute
	orphanMinAge      = time.Hour
	fileExt           = ".cast"
)

// Manager is the process-wide recording service. Create it once with New and
// start the background loops with Run.
type Manager struct {
	store *store.Store
	audit *audit.Logger
	dir   string

	dirErr error // non-nil when the directory isn't usable; recording is skipped

	settingsMu sync.RWMutex
	settings   models.RecordingSettings

	liveMu sync.Mutex
	live   map[*Session]struct{}

	diskMu sync.Mutex // serializes quota checks + eviction
	kick   chan struct{}
}

// Usage is what the admin settings screen shows next to the knobs.
type Usage struct {
	Dir           string `json:"dir"`
	DirWritable   bool   `json:"dirWritable"`
	DirError      string `json:"dirError,omitempty"`
	Count         int    `json:"count"`
	ActiveCount   int    `json:"activeCount"`
	UsedBytes     int64  `json:"usedBytes"`
	MaxTotalBytes int64  `json:"maxTotalBytes"`
	FreeBytes     int64  `json:"freeBytes"` // -1 when the platform can't tell
	MinFreeBytes  int64  `json:"minFreeBytes"`
	LimitReached  bool   `json:"limitReached"`
}

// New seeds settings from env (first boot only), prepares the directory and
// closes rows left open by a previous crash. A bad directory is not fatal:
// exec keeps working, it just isn't recorded.
func New(ctx context.Context, st *store.Store, auditLogger *audit.Logger, dir string, seed models.RecordingSettings) (*Manager, error) {
	if err := validate(&seed); err != nil {
		slog.Warn("invalid SESSION_RECORDING_* env, using defaults", slog.Any("error", err))
		seed = models.RecordingSettings{Enabled: seed.Enabled, RetentionDays: 30, MaxSessionMB: 10,
			MaxTotalMB: 2048, MinFreeMB: 512, DiskPolicy: models.RecordingPolicyEvictOldest}
	}
	if err := st.EnsureRecordingSettings(ctx, seed); err != nil {
		return nil, err
	}
	settings, err := st.GetRecordingSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("load recording settings: %w", err)
	}
	m := &Manager{
		store:    st,
		audit:    auditLogger,
		dir:      dir,
		settings: settings,
		live:     make(map[*Session]struct{}),
		kick:     make(chan struct{}, 1),
	}
	m.dirErr = prepareDir(dir)
	if m.dirErr != nil {
		slog.Warn("session recording directory unusable; exec sessions will not be recorded",
			slog.String("dir", dir), slog.Any("error", m.dirErr))
	}
	m.recoverOpen(ctx)
	slog.Info("session recording ready",
		slog.String("dir", dir),
		slog.Bool("enabled", settings.Enabled),
		slog.Int("retention_days", settings.RetentionDays),
		slog.Int("max_session_mb", settings.MaxSessionMB),
		slog.Int("max_total_mb", settings.MaxTotalMB),
		slog.String("disk_policy", settings.DiskPolicy),
	)
	return m, nil
}

// Run starts the retention and disk-guard loops; they stop with ctx.
func (m *Manager) Run(ctx context.Context) {
	go m.retentionLoop(ctx)
	go m.guardLoop(ctx)
}

// Settings returns the cached settings.
func (m *Manager) Settings() models.RecordingSettings {
	m.settingsMu.RLock()
	defer m.settingsMu.RUnlock()
	return m.settings
}

// UpdateSettings validates, persists and applies new settings, then kicks a
// retention pass so a shorter retention takes effect immediately. Sessions
// already in progress keep recording with the limits they started with.
func (m *Manager) UpdateSettings(ctx context.Context, in models.RecordingSettings) (models.RecordingSettings, error) {
	if err := validate(&in); err != nil {
		return in, err
	}
	if err := m.store.UpdateRecordingSettings(ctx, in); err != nil {
		return in, fmt.Errorf("save recording settings: %w", err)
	}
	m.settingsMu.Lock()
	m.settings = in
	m.settingsMu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
	return in, nil
}

// ValidationError marks a settings payload the admin needs to fix.
type ValidationError struct{ msg string }

func (e ValidationError) Error() string { return e.msg }

func validate(s *models.RecordingSettings) error {
	if s.DiskPolicy == "" {
		s.DiskPolicy = models.RecordingPolicyEvictOldest
	}
	switch {
	case s.RetentionDays < 0 || s.RetentionDays > 3650:
		return ValidationError{"retentionDays must be between 0 and 3650"}
	case s.MaxSessionMB < 1 || s.MaxSessionMB > 1024:
		return ValidationError{"maxSessionMb must be between 1 and 1024"}
	case s.MaxTotalMB < s.MaxSessionMB:
		return ValidationError{"maxTotalMb must be at least maxSessionMb"}
	case s.MinFreeMB < 0:
		return ValidationError{"minFreeMb must be >= 0"}
	case s.DiskPolicy != models.RecordingPolicyEvictOldest && s.DiskPolicy != models.RecordingPolicyStop:
		return ValidationError{"diskPolicy must be evict_oldest or stop"}
	}
	return nil
}

// Start opens a recording for a new exec session. It returns ErrDisabled when
// recording is off and ErrNoSpace when the disk guard refuses; any other
// error means the file or DB row could not be created.
func (m *Manager) Start(ctx context.Context, meta Meta) (*Session, error) {
	settings := m.Settings()
	if !settings.Enabled {
		return nil, ErrDisabled
	}
	if m.dirErr != nil {
		return nil, fmt.Errorf("recording dir unusable: %w", m.dirErr)
	}
	maxBytes := int64(settings.MaxSessionMB) * mb
	if err := m.ensureSpace(ctx, maxBytes); err != nil {
		return nil, err
	}

	sessionID := newUUID()
	path := filepath.Join(m.dir, sessionID+fileExt)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("create cast file: %w", err)
	}
	start := time.Now()
	rowID, err := m.store.CreateRecording(ctx, models.SessionRecording{
		SessionID: sessionID,
		User:      meta.User,
		Cluster:   meta.Cluster,
		Namespace: meta.Namespace,
		Pod:       meta.Pod,
		Container: meta.Container,
		StartedAt: start,
		RequestID: meta.RequestID,
		Path:      path,
	})
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	s := &Session{
		m:         m,
		rowID:     rowID,
		sessionID: sessionID,
		path:      path,
		meta:      meta,
		start:     start,
		maxBytes:  maxBytes,
		f:         f,
		w:         bufio.NewWriterSize(f, 32*1024),
		cols:      meta.Cols,
		rows:      meta.Rows,
		lastFlush: start,
	}
	m.liveMu.Lock()
	m.live[s] = struct{}{}
	m.liveMu.Unlock()
	return s, nil
}

// finish is called by Session.Close.
func (m *Manager) finish(s *Session, res Result) {
	m.liveMu.Lock()
	delete(m.live, s)
	m.liveMu.Unlock()
	if err := m.store.FinishRecording(context.Background(), s.rowID, time.Now(), res.SizeBytes, res.Truncated); err != nil {
		slog.Warn("finish recording row failed", slog.String("session_id", s.sessionID), slog.Any("error", err))
	}
}

// Get returns one recording's metadata.
func (m *Manager) Get(ctx context.Context, id int) (*models.SessionRecording, error) {
	rec, err := m.store.GetRecording(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return rec, err
}

// List proxies to the store.
func (m *Manager) List(ctx context.Context, f models.RecordingFilter) ([]models.SessionRecording, int, error) {
	return m.store.ListRecordings(ctx, f)
}

// Delete removes a finished recording's file and row.
func (m *Manager) Delete(ctx context.Context, id int) (*models.SessionRecording, error) {
	rec, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec.EndedAt == nil {
		return rec, ErrActive
	}
	return rec, m.remove(ctx, *rec)
}

func (m *Manager) remove(ctx context.Context, rec models.SessionRecording) error {
	if err := os.Remove(rec.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cast file: %w", err)
	}
	return m.store.DeleteRecording(ctx, rec.ID)
}

// Usage reports disk usage against the configured limits.
func (m *Manager) Usage(ctx context.Context) (Usage, error) {
	settings := m.Settings()
	count, used, err := m.usedBytes(ctx)
	if err != nil {
		return Usage{}, err
	}
	m.liveMu.Lock()
	active := len(m.live)
	m.liveMu.Unlock()
	u := Usage{
		Dir:           m.dir,
		DirWritable:   m.dirErr == nil,
		Count:         count,
		ActiveCount:   active,
		UsedBytes:     used,
		MaxTotalBytes: int64(settings.MaxTotalMB) * mb,
		FreeBytes:     -1,
		MinFreeBytes:  int64(settings.MinFreeMB) * mb,
	}
	if m.dirErr != nil {
		u.DirError = m.dirErr.Error()
	}
	if free, ok := diskFree(m.dir); ok {
		u.FreeBytes = int64(free)
	}
	// Same rule Start applies: a new session needs room for a full
	// max-size recording, so "reached" means the next one would not fit.
	reserve := int64(settings.MaxSessionMB) * mb
	u.LimitReached = u.UsedBytes+reserve > u.MaxTotalBytes ||
		(u.FreeBytes >= 0 && u.FreeBytes-reserve < u.MinFreeBytes)
	return u, nil
}

// usedBytes = finished rows from the DB + live sessions from memory.
func (m *Manager) usedBytes(ctx context.Context) (int, int64, error) {
	count, used, err := m.store.RecordingStats(ctx)
	if err != nil {
		return 0, 0, err
	}
	m.liveMu.Lock()
	for s := range m.live {
		used += s.Size()
	}
	m.liveMu.Unlock()
	return count, used, nil
}

// ensureSpace makes room for `reserve` more bytes under both the total quota
// and the free-space floor, evicting the oldest finished recordings when the
// policy allows it.
func (m *Manager) ensureSpace(ctx context.Context, reserve int64) error {
	m.diskMu.Lock()
	defer m.diskMu.Unlock()
	settings := m.Settings()
	maxTotal := int64(settings.MaxTotalMB) * mb
	minFree := int64(settings.MinFreeMB) * mb

	for {
		_, used, err := m.usedBytes(ctx)
		if err != nil {
			return err
		}
		overQuota := used+reserve > maxTotal
		lowDisk := false
		if free, ok := diskFree(m.dir); ok {
			lowDisk = int64(free)-reserve < minFree
		}
		if !overQuota && !lowDisk {
			return nil
		}
		if settings.DiskPolicy != models.RecordingPolicyEvictOldest {
			return ErrNoSpace
		}
		victims, err := m.store.ListOldestFinishedRecordings(ctx, 1)
		if err != nil {
			return err
		}
		if len(victims) == 0 {
			return ErrNoSpace
		}
		v := victims[0]
		if err := m.remove(ctx, v); err != nil {
			slog.Warn("recording eviction failed", slog.String("session_id", v.SessionID), slog.Any("error", err))
			return ErrNoSpace
		}
		reason := "quota"
		if lowDisk {
			reason = "low_disk"
		}
		m.recordSystemAudit("recording.evicted", v, "reason="+reason+";size="+strconv.FormatInt(v.SizeBytes, 10))
	}
}

// guardLoop re-checks the quota while sessions are live, so a burst of
// concurrent sessions can't run the volume dry between Start calls.
func (m *Manager) guardLoop(ctx context.Context) {
	t := time.NewTicker(guardInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.liveMu.Lock()
		live := make([]*Session, 0, len(m.live))
		for s := range m.live {
			live = append(live, s)
		}
		m.liveMu.Unlock()
		if len(live) == 0 {
			continue
		}
		if err := m.ensureSpace(ctx, 0); errors.Is(err, ErrNoSpace) {
			slog.Warn("recording disk limit reached; stopping live recordings", slog.Int("sessions", len(live)))
			for _, s := range live {
				s.Stop(ReasonDiskQuota)
			}
		}
	}
}

func (m *Manager) retentionLoop(ctx context.Context) {
	timer := time.NewTimer(retentionDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(retentionInterval)
		case <-m.kick:
		}
		m.purge(ctx)
	}
}

// purge drops recordings past retention and orphan .cast files on disk.
func (m *Manager) purge(ctx context.Context) {
	if days := m.Settings().RetentionDays; days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		old, err := m.store.ListRecordingsStartedBefore(ctx, cutoff)
		if err != nil {
			slog.Warn("recording retention query failed", slog.Any("error", err))
		}
		removed := 0
		var freed int64
		for _, rec := range old {
			if err := m.remove(ctx, rec); err != nil {
				slog.Warn("recording retention delete failed", slog.String("session_id", rec.SessionID), slog.Any("error", err))
				continue
			}
			removed++
			freed += rec.SizeBytes
		}
		if removed > 0 {
			slog.Info("recording retention purge", slog.Int("removed", removed), slog.Int64("freed_bytes", freed))
			go m.audit.Record(context.Background(), models.AuditLog{
				User:         "system",
				Action:       "recording.purge",
				Namespace:    "-",
				ResourceType: "recording",
				ResourceName: "count=" + strconv.Itoa(removed) + ";retention_days=" + strconv.Itoa(days),
			})
		}
	}
	m.sweepOrphans(ctx)
}

// sweepOrphans removes .cast files with no DB row (e.g. the row insert failed
// after the file was created, or a row was deleted by hand).
func (m *Manager) sweepOrphans(ctx context.Context) {
	if m.dirErr != nil {
		return
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	known, err := m.store.RecordingSessionIDs(ctx)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, fileExt) {
			continue
		}
		if _, ok := known[strings.TrimSuffix(name, fileExt)]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < orphanMinAge {
			continue
		}
		if err := os.Remove(filepath.Join(m.dir, name)); err == nil {
			slog.Info("removed orphan recording file", slog.String("file", name))
		}
	}
}

// recoverOpen closes rows a crash left open, using the file's size and mtime.
func (m *Manager) recoverOpen(ctx context.Context) {
	open, err := m.store.ListOpenRecordings(ctx)
	if err != nil {
		slog.Warn("recording recovery query failed", slog.Any("error", err))
		return
	}
	for _, rec := range open {
		ended, size := rec.StartedAt, int64(0)
		if info, err := os.Stat(rec.Path); err == nil {
			ended, size = info.ModTime(), info.Size()
		}
		if err := m.store.FinishRecording(ctx, rec.ID, ended, size, false); err != nil {
			slog.Warn("recording recovery failed", slog.String("session_id", rec.SessionID), slog.Any("error", err))
			continue
		}
		slog.Info("closed interrupted recording", slog.String("session_id", rec.SessionID), slog.Int64("size_bytes", size))
	}
}

func (m *Manager) recordSystemAudit(action string, rec models.SessionRecording, detail string) {
	go m.audit.Record(context.Background(), models.AuditLog{
		User:         "system",
		Action:       action,
		Namespace:    rec.Namespace,
		ResourceType: "recording",
		ResourceName: rec.Pod + " (session_id=" + rec.SessionID + ";" + detail + ")",
	})
}

func prepareDir(dir string) error {
	if dir == "" {
		return errors.New("empty directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
