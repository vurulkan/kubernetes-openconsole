package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// CreateSession records a newly-issued token so AuthMiddleware can later
// enforce admin-driven revocation. The caller derives the jti and signs the
// JWT in parallel; keeping both in sync is the caller's job.
func (s *Store) CreateSession(ctx context.Context, jti string, userID int, issuedAt, expiresAt time.Time, ip, userAgent string) error {
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO session_tokens (jti, user_id, issued_at, last_used_at, expires_at, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		jti, userID, issuedAt.UTC(), issuedAt.UTC(), expiresAt.UTC(), ip, userAgent,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// SessionStatus is what AuthMiddleware needs per request. Keeping this
// deliberately narrow avoids an N+1 of full-row scans on every API call.
type SessionStatus struct {
	Found   bool
	Revoked bool
	Expired bool
	UserID  int
}

// LookupSession returns the current state of a session row. A row that does
// not exist (Found=false) is treated as "pre-tracking" by the middleware so
// JWTs issued before the session_tokens migration keep working until they
// expire naturally.
func (s *Store) LookupSession(ctx context.Context, jti string) (SessionStatus, error) {
	if jti == "" {
		return SessionStatus{}, nil
	}
	var (
		userID    int
		revokedAt sql.NullTime
		expiresAt time.Time
	)
	err := s.conn.QueryRowContext(ctx,
		`SELECT user_id, revoked_at, expires_at FROM session_tokens WHERE jti = ?`,
		jti,
	).Scan(&userID, &revokedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return SessionStatus{}, nil
	}
	if err != nil {
		return SessionStatus{}, fmt.Errorf("lookup session: %w", err)
	}
	return SessionStatus{
		Found:   true,
		Revoked: revokedAt.Valid,
		Expired: time.Now().UTC().After(expiresAt),
		UserID:  userID,
	}, nil
}

// TouchSession bumps last_used_at. Called from a goroutine so a long-running
// request isn't delayed by the write. Callers upstream throttle so we don't
// hammer SQLite on every API call.
func (s *Store) TouchSession(ctx context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	_, err := s.conn.ExecContext(ctx,
		`UPDATE session_tokens SET last_used_at = ? WHERE jti = ?`,
		time.Now().UTC(), jti,
	)
	return err
}

// RevokeSession marks a single session as revoked. Idempotent: calling it on
// an already-revoked row is a no-op.
func (s *Store) RevokeSession(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE session_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id,
	)
	return err
}

// RevokeAllForUser kills every active session for a user. Used by
// change-password and by the Admin "Revoke all" button.
func (s *Store) RevokeAllForUser(ctx context.Context, userID int) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE session_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), userID,
	)
	return err
}

// ListSessions returns every session (optionally filtered to one user, or
// only active ones). Rows come back newest-issued-first so the Admin table
// defaults to the useful order.
func (s *Store) ListSessions(ctx context.Context, userID int, activeOnly bool) ([]models.SessionTokenRow, error) {
	q := `SELECT s.id, s.jti, s.user_id, u.username, s.issued_at, s.last_used_at, s.expires_at, s.revoked_at, s.ip, s.user_agent
	      FROM session_tokens s LEFT JOIN users u ON u.id = s.user_id`
	args := []any{}
	where := []string{}
	if userID > 0 {
		where = append(where, "s.user_id = ?")
		args = append(args, userID)
	}
	if activeOnly {
		where = append(where, "s.revoked_at IS NULL")
		where = append(where, "s.expires_at > ?")
		args = append(args, time.Now().UTC())
	}
	for i, w := range where {
		if i == 0 {
			q += " WHERE " + w
		} else {
			q += " AND " + w
		}
	}
	q += " ORDER BY s.issued_at DESC LIMIT 500"
	rows, err := s.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var out []models.SessionTokenRow
	for rows.Next() {
		var r models.SessionTokenRow
		var username sql.NullString
		var revokedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.JTI, &r.UserID, &username, &r.IssuedAt, &r.LastUsedAt, &r.ExpiresAt, &revokedAt, &r.IP, &r.UserAgent); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		if username.Valid {
			r.Username = username.String
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			r.RevokedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeExpiredSessions removes rows that are past their expiry AND revoked at
// least 24h ago. Called opportunistically; keeping a trailing window of
// revoked rows is useful for auditing a recent incident.
func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	_, err := s.conn.ExecContext(ctx,
		`DELETE FROM session_tokens
		 WHERE (expires_at < ? AND (revoked_at IS NULL OR revoked_at < ?))`,
		cutoff, cutoff,
	)
	return err
}

// ─── In-memory last-used throttle ───────────────────────────────────────────
//
// Every authenticated request would otherwise fire an UPDATE on
// session_tokens; on SQLite with a single open connection that serializes
// requests behind one another and shows up on p95. The throttle keeps a
// per-jti timestamp and defers the write unless we're overdue.

const touchInterval = 30 * time.Second

// SessionToucher batches last_used_at writes. Zero value is NOT ready — call
// NewSessionToucher.
type SessionToucher struct {
	store *Store
	mu    sync.Mutex
	last  map[string]time.Time
}

func NewSessionToucher(s *Store) *SessionToucher {
	return &SessionToucher{store: s, last: map[string]time.Time{}}
}

// Touch fires an UPDATE in the background if the jti hasn't been touched in
// the last throttle window. Safe to call from the hot path; it is
// non-blocking.
func (t *SessionToucher) Touch(jti string) {
	if jti == "" {
		return
	}
	t.mu.Lock()
	prev := t.last[jti]
	now := time.Now()
	if now.Sub(prev) < touchInterval {
		t.mu.Unlock()
		return
	}
	t.last[jti] = now
	t.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = t.store.TouchSession(ctx, jti)
	}()
}

// Forget drops the in-memory throttle entry for a jti — called on explicit
// revoke so the next touch (shouldn't happen, but belt-and-braces) doesn't
// resurrect bookkeeping for a dead row.
func (t *SessionToucher) Forget(jti string) {
	t.mu.Lock()
	delete(t.last, jti)
	t.mu.Unlock()
}
