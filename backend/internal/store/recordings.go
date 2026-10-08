package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/models"
)

const recordingColumns = `id, session_id, user, cluster, namespace, pod, container,
	started_at, ended_at, size_bytes, truncated, request_id, path`

// EnsureRecordingSettings seeds the singleton settings row on first boot.
// An existing row is left untouched so admin edits survive restarts.
func (s *Store) EnsureRecordingSettings(ctx context.Context, seed models.RecordingSettings) error {
	_, err := s.conn.ExecContext(ctx,
		`INSERT OR IGNORE INTO recording_settings
		 (id, enabled, retention_days, max_session_mb, max_total_mb, min_free_mb, disk_policy)
		 VALUES (1, ?, ?, ?, ?, ?, ?)`,
		boolToInt(seed.Enabled), seed.RetentionDays, seed.MaxSessionMB,
		seed.MaxTotalMB, seed.MinFreeMB, seed.DiskPolicy,
	)
	if err != nil {
		return fmt.Errorf("seed recording settings: %w", err)
	}
	return nil
}

func (s *Store) GetRecordingSettings(ctx context.Context) (models.RecordingSettings, error) {
	var (
		out     models.RecordingSettings
		enabled int
	)
	err := s.conn.QueryRowContext(ctx,
		`SELECT enabled, retention_days, max_session_mb, max_total_mb, min_free_mb, disk_policy
		 FROM recording_settings WHERE id = 1`,
	).Scan(&enabled, &out.RetentionDays, &out.MaxSessionMB, &out.MaxTotalMB, &out.MinFreeMB, &out.DiskPolicy)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled == 1
	return out, nil
}

func (s *Store) UpdateRecordingSettings(ctx context.Context, in models.RecordingSettings) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE recording_settings SET enabled = ?, retention_days = ?, max_session_mb = ?,
		 max_total_mb = ?, min_free_mb = ?, disk_policy = ? WHERE id = 1`,
		boolToInt(in.Enabled), in.RetentionDays, in.MaxSessionMB, in.MaxTotalMB, in.MinFreeMB, in.DiskPolicy,
	)
	return err
}

func (s *Store) CreateRecording(ctx context.Context, rec models.SessionRecording) (int, error) {
	res, err := s.conn.ExecContext(ctx,
		`INSERT INTO session_recordings
		 (session_id, user, cluster, namespace, pod, container, started_at, request_id, path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.SessionID, rec.User, rec.Cluster, rec.Namespace, rec.Pod, rec.Container,
		rec.StartedAt.UTC(), rec.RequestID, rec.Path,
	)
	if err != nil {
		return 0, fmt.Errorf("create recording: %w", err)
	}
	id, err := res.LastInsertId()
	return int(id), err
}

func (s *Store) FinishRecording(ctx context.Context, id int, endedAt time.Time, sizeBytes int64, truncated bool) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE session_recordings SET ended_at = ?, size_bytes = ?, truncated = ? WHERE id = ?`,
		endedAt.UTC(), sizeBytes, boolToInt(truncated), id,
	)
	return err
}

func (s *Store) GetRecording(ctx context.Context, id int) (*models.SessionRecording, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT `+recordingColumns+` FROM session_recordings WHERE id = ?`, id)
	rec, err := scanRecording(row)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListRecordings returns one page (newest first) plus the total match count.
func (s *Store) ListRecordings(ctx context.Context, f models.RecordingFilter) ([]models.SessionRecording, int, error) {
	conditions := []string{}
	args := []interface{}{}
	like := func(col, v string) {
		if v != "" {
			conditions = append(conditions, col+" LIKE ?")
			args = append(args, "%"+v+"%")
		}
	}
	like("user", f.User)
	like("cluster", f.Cluster)
	like("namespace", f.Namespace)
	like("pod", f.Pod)
	if f.From != nil {
		conditions = append(conditions, "started_at >= ?")
		args = append(args, f.From.UTC())
	}
	if f.To != nil {
		conditions = append(conditions, "started_at <= ?")
		args = append(args, f.To.UTC())
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM session_recordings`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.conn.QueryContext(ctx,
		`SELECT `+recordingColumns+` FROM session_recordings`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items, err := scanRecordings(rows)
	return items, total, err
}

// ListRecordingsStartedBefore returns finished recordings older than cutoff,
// used by retention.
func (s *Store) ListRecordingsStartedBefore(ctx context.Context, cutoff time.Time) ([]models.SessionRecording, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT `+recordingColumns+` FROM session_recordings
		 WHERE ended_at IS NOT NULL AND started_at < ? ORDER BY id ASC`, cutoff.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecordings(rows)
}

// ListOldestFinishedRecordings returns up to limit finished recordings,
// oldest first — the eviction order when the disk quota is hit.
func (s *Store) ListOldestFinishedRecordings(ctx context.Context, limit int) ([]models.SessionRecording, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT `+recordingColumns+` FROM session_recordings
		 WHERE ended_at IS NOT NULL ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecordings(rows)
}

// ListOpenRecordings returns rows with no ended_at — only meaningful at
// startup, when no session can actually be live.
func (s *Store) ListOpenRecordings(ctx context.Context) ([]models.SessionRecording, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT `+recordingColumns+` FROM session_recordings WHERE ended_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecordings(rows)
}

// RecordingStats returns the number of rows and the summed size of finished
// recordings (open sessions report 0 until they end).
func (s *Store) RecordingStats(ctx context.Context) (count int, totalBytes int64, err error) {
	err = s.conn.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM session_recordings`,
	).Scan(&count, &totalBytes)
	return
}

// RecordingSessionIDs returns every known session id, used to spot orphan
// .cast files on disk.
func (s *Store) RecordingSessionIDs(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT session_id FROM session_recordings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecording(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM session_recordings WHERE id = ?`, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecording(row rowScanner) (models.SessionRecording, error) {
	var (
		rec       models.SessionRecording
		endedAt   sql.NullTime
		truncated int
	)
	err := row.Scan(&rec.ID, &rec.SessionID, &rec.User, &rec.Cluster, &rec.Namespace, &rec.Pod,
		&rec.Container, &rec.StartedAt, &endedAt, &rec.SizeBytes, &truncated, &rec.RequestID, &rec.Path)
	if err != nil {
		return rec, err
	}
	rec.Truncated = truncated == 1
	if endedAt.Valid {
		t := endedAt.Time
		rec.EndedAt = &t
		rec.DurationMs = t.Sub(rec.StartedAt).Milliseconds()
	}
	return rec, nil
}

func scanRecordings(rows *sql.Rows) ([]models.SessionRecording, error) {
	items := []models.SessionRecording{}
	for rows.Next() {
		rec, err := scanRecording(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, rec)
	}
	return items, rows.Err()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
