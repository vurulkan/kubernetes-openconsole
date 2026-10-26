package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// RecordTermination stores one observed container exit. The informers see the
// same exit again on resync and on every OpenConsole start, so an exit no newer
// than the container's last row is ignored; an exit identical to the last one
// (same code and reason) extends that row instead of adding one, which keeps a
// crash-looping container to a single row.
func (s *Store) RecordTermination(ctx context.Context, clusterID int, t models.ContainerTermination) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id       int64
		exitCode int
		reason   string
		lastAt   time.Time
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, exit_code, reason, last_at FROM restart_history
		 WHERE cluster_id = ? AND namespace = ? AND pod = ? AND container = ?
		 ORDER BY last_at DESC LIMIT 1`,
		clusterID, t.Namespace, t.Pod, t.Container).Scan(&id, &exitCode, &reason, &lastAt)
	at := t.LastAt.UTC()
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	case !at.After(lastAt):
		return nil // already recorded
	case exitCode == t.ExitCode && reason == t.Reason:
		if _, err := tx.ExecContext(ctx,
			`UPDATE restart_history SET count = count + 1, last_at = ? WHERE id = ?`, at, id); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO restart_history
		   (cluster_id, namespace, pod, container, owner, exit_code, signal, reason, first_at, last_at, count)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		clusterID, t.Namespace, t.Pod, t.Container, t.Owner, t.ExitCode, t.Signal, t.Reason, at, at); err != nil {
		return err
	}
	return tx.Commit()
}

// ListTerminations returns a pod's (pod != "") or a workload's (owner,
// "Deployment/web") restart history since a time, newest first.
func (s *Store) ListTerminations(ctx context.Context, clusterID int, namespace, owner, pod string, since time.Time, limit int) ([]models.ContainerTermination, error) {
	q := `SELECT namespace, pod, container, owner, exit_code, signal, reason, first_at, last_at, count
	      FROM restart_history WHERE cluster_id = ? AND namespace = ? AND last_at >= ?`
	args := []any{clusterID, namespace, since.UTC()}
	if pod != "" {
		q += ` AND pod = ?`
		args = append(args, pod)
	} else {
		q += ` AND owner = ?`
		args = append(args, owner)
	}
	q += ` ORDER BY last_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ContainerTermination{}
	for rows.Next() {
		var t models.ContainerTermination
		if err := rows.Scan(&t.Namespace, &t.Pod, &t.Container, &t.Owner, &t.ExitCode, &t.Signal, &t.Reason,
			&t.FirstAt, &t.LastAt, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClusterTerminations returns every restart row of a cluster whose last exit is since or later.
func (s *Store) ClusterTerminations(ctx context.Context, clusterID int, since time.Time) ([]models.ContainerTermination, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT namespace, pod, container, owner, exit_code, signal, reason, first_at, last_at, count
		 FROM restart_history WHERE cluster_id = ? AND last_at >= ?`, clusterID, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ContainerTermination{}
	for rows.Next() {
		var t models.ContainerTermination
		if err := rows.Scan(&t.Namespace, &t.Pod, &t.Container, &t.Owner, &t.ExitCode, &t.Signal, &t.Reason,
			&t.FirstAt, &t.LastAt, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PurgeTerminations drops history whose last exit is older than before.
func (s *Store) PurgeTerminations(ctx context.Context, before time.Time) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM restart_history WHERE last_at < ?`, before.UTC())
	return err
}
