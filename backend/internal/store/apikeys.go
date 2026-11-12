package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// ErrAPIKeyNameTaken: the user already has a key with that name.
var ErrAPIKeyNameTaken = errors.New("an API key with this name already exists")

const apiKeyColumns = `id, user_id, name, note, prefix, hash, admin_scope, all_namespaces,
	created_at, updated_at, expires_at, last_used_at, last_used_ip, revoked_at`

// CreateAPIKey stores a new key with its scope and returns its id.
func (s *Store) CreateAPIKey(ctx context.Context, k models.APIKey) (int, error) {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `INSERT INTO api_keys
		(user_id, name, note, prefix, hash, admin_scope, all_namespaces, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.UserID, k.Name, k.Note, k.Prefix, k.Hash, boolToInt(k.AdminScope), boolToInt(k.AllNamespaces), now, now, utcOrNil(k.ExpiresAt))
	if err != nil {
		return 0, nameTaken(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := writeAPIKeyScope(ctx, tx, int(id), k.APIKeyScope); err != nil {
		return 0, err
	}
	return int(id), tx.Commit()
}

// UpdateAPIKey changes name, note, admin scope and scope; the secret and the expiry stay.
func (s *Store) UpdateAPIKey(ctx context.Context, k models.APIKey) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE api_keys SET name = ?, note = ?, admin_scope = ?, all_namespaces = ?, updated_at = ?
		WHERE id = ?`, k.Name, k.Note, boolToInt(k.AdminScope), boolToInt(k.AllNamespaces), time.Now().UTC(), k.ID); err != nil {
		return nameTaken(err)
	}
	for _, q := range []string{`DELETE FROM api_key_scopes WHERE key_id = ?`, `DELETE FROM api_key_permissions WHERE key_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, k.ID); err != nil {
			return err
		}
	}
	if err := writeAPIKeyScope(ctx, tx, k.ID, k.APIKeyScope); err != nil {
		return err
	}
	return tx.Commit()
}

// RegenerateAPIKey replaces the secret and the expiry; a revoked key becomes usable again.
func (s *Store) RegenerateAPIKey(ctx context.Context, id int, prefix, hash string, expiresAt *time.Time) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE api_keys SET prefix = ?, hash = ?, expires_at = ?, revoked_at = NULL, updated_at = ?
		WHERE id = ?`, prefix, hash, utcOrNil(expiresAt), time.Now().UTC(), id)
	return err
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int) error {
	now := time.Now().UTC()
	_, err := s.conn.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL`, now, now, id)
	return err
}

// RevokeUserAPIKeys revokes every live key of the user and returns how many.
func (s *Store) RevokeUserAPIKeys(ctx context.Context, userID int) (int, error) {
	now := time.Now().UTC()
	res, err := s.conn.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ?, updated_at = ?
		WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, now, now, userID, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *Store) DeleteAPIKey(ctx context.Context, id int) error {
	for _, q := range []string{`DELETE FROM api_key_scopes WHERE key_id = ?`, `DELETE FROM api_key_permissions WHERE key_id = ?`, `DELETE FROM api_keys WHERE id = ?`} {
		if _, err := s.conn.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return nil
}

// TouchAPIKey records the last use (see the throttle in the api package).
func (s *Store) TouchAPIKey(ctx context.Context, id int, ip string) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ?, last_used_ip = ? WHERE id = ?`, time.Now().UTC(), ip, id)
	return err
}

// ListAPIKeys returns the user's keys (userID 0 = every user's), newest first.
func (s *Store) ListAPIKeys(ctx context.Context, userID int) ([]models.APIKey, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE ? = 0 OR user_id = ? ORDER BY id DESC`, userID, userID)
	if err != nil {
		return nil, err
	}
	out := []models.APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].APIKeyScope, err = s.apiKeyScope(ctx, out[i].ID, out[i].AllNamespaces); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetAPIKey returns a key with its scope (sql.ErrNoRows when missing).
func (s *Store) GetAPIKey(ctx context.Context, id int) (*models.APIKey, error) {
	return s.getAPIKey(ctx, `id = ?`, id)
}

// GetAPIKeyByHash finds a key by the SHA-256 of its secret (sql.ErrNoRows when missing).
func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	return s.getAPIKey(ctx, `hash = ?`, hash)
}

func (s *Store) getAPIKey(ctx context.Context, where string, arg any) (*models.APIKey, error) {
	k, err := scanAPIKey(s.conn.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE `+where, arg))
	if err != nil {
		return nil, err
	}
	if k.APIKeyScope, err = s.apiKeyScope(ctx, k.ID, k.AllNamespaces); err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) apiKeyScope(ctx context.Context, id int, all bool) (models.APIKeyScope, error) {
	sc := models.APIKeyScope{Clusters: []int{}, AllNamespaces: all, Namespaces: []string{}, Grants: []string{}}
	rows, err := s.conn.QueryContext(ctx, `SELECT DISTINCT cluster_id, namespace FROM api_key_scopes WHERE key_id = ? ORDER BY cluster_id, namespace`, id)
	if err != nil {
		return sc, err
	}
	clusters, namespaces := map[int]bool{}, map[string]bool{}
	for rows.Next() {
		var c int
		var ns string
		if err := rows.Scan(&c, &ns); err != nil {
			rows.Close()
			return sc, err
		}
		if !clusters[c] {
			clusters[c] = true
			sc.Clusters = append(sc.Clusters, c)
		}
		if ns != "" && !namespaces[ns] {
			namespaces[ns] = true
			sc.Namespaces = append(sc.Namespaces, ns)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return sc, err
	}
	rows, err = s.conn.QueryContext(ctx, `SELECT resource, action FROM api_key_permissions WHERE key_id = ? ORDER BY rowid`, id)
	if err != nil {
		return sc, err
	}
	defer rows.Close()
	for rows.Next() {
		var res, act string
		if err := rows.Scan(&res, &act); err != nil {
			return sc, err
		}
		sc.Grants = append(sc.Grants, res+":"+act)
	}
	return sc, rows.Err()
}

// writeAPIKeyScope stores clusters × namespaces (namespace ” when the key
// has every namespace) and the grants.
func writeAPIKeyScope(ctx context.Context, tx *sql.Tx, id int, sc models.APIKeyScope) error {
	namespaces := sc.Namespaces
	if sc.AllNamespaces {
		namespaces = []string{""}
	}
	for _, c := range sc.Clusters {
		for _, ns := range namespaces {
			if _, err := tx.ExecContext(ctx, `INSERT INTO api_key_scopes (key_id, cluster_id, namespace) VALUES (?, ?, ?)`, id, c, ns); err != nil {
				return err
			}
		}
	}
	for _, g := range sc.Grants {
		res, act, _ := strings.Cut(g, ":")
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_key_permissions (key_id, resource, action) VALUES (?, ?, ?)`, id, res, act); err != nil {
			return err
		}
	}
	return nil
}

func scanAPIKey(row rowScanner) (models.APIKey, error) {
	var (
		k                          models.APIKey
		admin, all                 int
		expires, lastUsed, revoked sql.NullTime
	)
	err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Note, &k.Prefix, &k.Hash, &admin, &all,
		&k.CreatedAt, &k.UpdatedAt, &expires, &lastUsed, &k.LastUsedIP, &revoked)
	if err != nil {
		return k, err
	}
	k.AdminScope, k.AllNamespaces = admin == 1, all == 1
	k.ExpiresAt, k.LastUsedAt, k.RevokedAt = timePtr(expires), timePtr(lastUsed), timePtr(revoked)
	return k, nil
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func utcOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func nameTaken(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: api_keys.user_id, api_keys.name") {
		return ErrAPIKeyNameTaken
	}
	return err
}
