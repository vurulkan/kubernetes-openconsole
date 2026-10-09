package store

import (
	"context"
	"time"

	"k8s-dashboard/backend/internal/models"
)

const viewColumns = `v.id, v.user_id, u.username, v.name, COALESCE(v.cluster_id, 0), COALESCE(c.name, ''),
	v.namespace, v.tab, v.search, v.view_mode, v.shared, v.created_at`

const viewFrom = ` FROM saved_views v
	JOIN users u ON u.id = v.user_id
	LEFT JOIN clusters c ON c.id = v.cluster_id`

// ListViewsFor returns the user's own views plus views others shared.
func (s *Store) ListViewsFor(ctx context.Context, userID int) ([]models.SavedView, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT `+viewColumns+viewFrom+`
		WHERE v.user_id = ? OR v.shared = 1
		ORDER BY (v.user_id = ?) DESC, v.name`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.SavedView{}
	for rows.Next() {
		v, err := scanView(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetView(ctx context.Context, id int) (*models.SavedView, error) {
	v, err := scanView(s.conn.QueryRowContext(ctx, `SELECT `+viewColumns+viewFrom+` WHERE v.id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// SaveView creates the view, or replaces the user's view with the same name.
func (s *Store) SaveView(ctx context.Context, v models.SavedView) (int, error) {
	var cluster any
	if v.ClusterID > 0 {
		cluster = v.ClusterID
	}
	_, err := s.conn.ExecContext(ctx, `INSERT INTO saved_views
		(user_id, name, cluster_id, namespace, tab, search, view_mode, shared, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, name) DO UPDATE SET
			cluster_id = excluded.cluster_id, namespace = excluded.namespace, tab = excluded.tab,
			search = excluded.search, view_mode = excluded.view_mode, shared = excluded.shared`,
		v.UserID, v.Name, cluster, v.Namespace, v.Tab, v.Search, v.ViewMode, boolToInt(v.Shared), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	var id int
	err = s.conn.QueryRowContext(ctx, `SELECT id FROM saved_views WHERE user_id = ? AND name = ?`, v.UserID, v.Name).Scan(&id)
	return id, err
}

func (s *Store) SetViewShared(ctx context.Context, id int, shared bool) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE saved_views SET shared = ? WHERE id = ?`, boolToInt(shared), id)
	return err
}

func (s *Store) DeleteView(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM saved_views WHERE id = ?`, id)
	return err
}

func scanView(row rowScanner) (models.SavedView, error) {
	var v models.SavedView
	var shared int
	err := row.Scan(&v.ID, &v.UserID, &v.Owner, &v.Name, &v.ClusterID, &v.ClusterName,
		&v.Namespace, &v.Tab, &v.Search, &v.ViewMode, &shared, &v.CreatedAt)
	v.Shared = shared == 1
	return v, err
}
