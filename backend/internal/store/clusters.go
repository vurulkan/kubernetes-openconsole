package store

import (
	"context"
	"fmt"

	"k8s-dashboard/backend/internal/models"
)

// Cluster is a saved connection to a Kubernetes API server. One row per
// cluster the operator has configured; exactly one is marked is_active and
// drives kube.Manager at any given time. Secrets are stored encrypted with
// the shared store key, same scheme as the legacy kube_credentials row.
type Cluster struct {
	ID          int                   `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	IsActive    bool                  `json:"isActive"`
	Credentials models.KubeCredentials `json:"-"`
	// Server is surfaced so the UI can show "where does this point" without
	// handing out the entire kubeconfig.
	Server    string `json:"server"`
	Method    string `json:"method"`
	CreatedAt string `json:"createdAt"`
}

func (s *Store) ListClusters(ctx context.Context) ([]Cluster, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT id, name, description, method, server, is_active, created_at
		 FROM clusters ORDER BY is_active DESC, name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cluster
	for rows.Next() {
		var c Cluster
		var active int
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Method, &c.Server, &active, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.IsActive = active == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCluster(ctx context.Context, id int) (*Cluster, error) {
	row := s.conn.QueryRowContext(ctx,
		`SELECT id, name, description, method, kubeconfig_enc, token_enc, server, ca_cert_enc, is_active, created_at
		 FROM clusters WHERE id = ?`, id,
	)
	var c Cluster
	var encKube, encToken, encCA string
	var active int
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &c.Method,
		&encKube, &encToken, &c.Server, &encCA, &active, &c.CreatedAt); err != nil {
		return nil, err
	}
	c.IsActive = active == 1
	kube, err := decrypt(s.key, encKube)
	if err != nil {
		return nil, err
	}
	tok, err := decrypt(s.key, encToken)
	if err != nil {
		return nil, err
	}
	ca, err := decrypt(s.key, encCA)
	if err != nil {
		return nil, err
	}
	c.Credentials = models.KubeCredentials{
		Method:     c.Method,
		Server:     c.Server,
		Kubeconfig: []byte(kube),
		Token:      []byte(tok),
		CACert:     []byte(ca),
		Active:     c.IsActive,
	}
	return &c, nil
}

func (s *Store) GetActiveCluster(ctx context.Context) (*Cluster, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT id FROM clusters WHERE is_active = 1 LIMIT 1`)
	var id int
	if err := row.Scan(&id); err != nil {
		return nil, err
	}
	return s.GetCluster(ctx, id)
}

func (s *Store) CreateCluster(ctx context.Context, name, description string, creds models.KubeCredentials) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("cluster name is required")
	}
	encKube, err := encrypt(s.key, string(creds.Kubeconfig))
	if err != nil {
		return 0, err
	}
	encToken, err := encrypt(s.key, string(creds.Token))
	if err != nil {
		return 0, err
	}
	encCA, err := encrypt(s.key, string(creds.CACert))
	if err != nil {
		return 0, err
	}
	res, err := s.conn.ExecContext(ctx,
		`INSERT INTO clusters (name, description, method, kubeconfig_enc, token_enc, server, ca_cert_enc, is_active)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		name, description, creds.Method, encKube, encToken, creds.Server, encCA,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return int(id), err
}

func (s *Store) UpdateCluster(ctx context.Context, id int, name, description string, creds models.KubeCredentials, replaceSecrets bool) error {
	if replaceSecrets {
		encKube, err := encrypt(s.key, string(creds.Kubeconfig))
		if err != nil {
			return err
		}
		encToken, err := encrypt(s.key, string(creds.Token))
		if err != nil {
			return err
		}
		encCA, err := encrypt(s.key, string(creds.CACert))
		if err != nil {
			return err
		}
		_, err = s.conn.ExecContext(ctx,
			`UPDATE clusters SET name = ?, description = ?, method = ?, kubeconfig_enc = ?, token_enc = ?, server = ?, ca_cert_enc = ? WHERE id = ?`,
			name, description, creds.Method, encKube, encToken, creds.Server, encCA, id,
		)
		return err
	}
	_, err := s.conn.ExecContext(ctx,
		`UPDATE clusters SET name = ?, description = ? WHERE id = ?`,
		name, description, id,
	)
	return err
}

func (s *Store) DeleteCluster(ctx context.Context, id int) error {
	// Prevent deleting the only active cluster; caller should activate another
	// first. We enforce this at the store level so API consumers can't bypass.
	var active int
	if err := s.conn.QueryRowContext(ctx, `SELECT is_active FROM clusters WHERE id = ?`, id).Scan(&active); err != nil {
		return err
	}
	if active == 1 {
		return fmt.Errorf("cannot delete the active cluster — activate another first")
	}
	_, err := s.conn.ExecContext(ctx, `DELETE FROM clusters WHERE id = ?`, id)
	return err
}

// DeactivateCluster clears the active flag — nothing is active afterwards.
// Dashboard reads will return "cluster not ready" until something is activated.
func (s *Store) DeactivateCluster(ctx context.Context, id int) error {
	res, err := s.conn.ExecContext(ctx,
		`UPDATE clusters SET is_active = 0 WHERE id = ? AND is_active = 1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cluster %d is not currently active", id)
	}
	return nil
}

func (s *Store) ActivateCluster(ctx context.Context, id int) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE clusters SET is_active = 0 WHERE is_active = 1`); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE clusters SET is_active = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cluster %d not found", id)
	}
	return tx.Commit()
}

// GetClusterName returns a cluster's name without decrypting credentials.
func (s *Store) GetClusterName(ctx context.Context, id int) (string, error) {
	var name string
	err := s.conn.QueryRowContext(ctx, `SELECT name FROM clusters WHERE id = ?`, id).Scan(&name)
	return name, err
}

// ClearClusterSelections resets users who had picked a (deleted) cluster back
// to the default.
func (s *Store) ClearClusterSelections(ctx context.Context, clusterID int) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET active_cluster_id = NULL WHERE active_cluster_id = ?`, clusterID)
	return err
}
