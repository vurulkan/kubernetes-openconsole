package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	Conn *sql.DB
}

func Open(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := migrate(context.Background(), conn); err != nil {
		return nil, err
	}

	return &DB{Conn: conn}, nil
}

func migrate(ctx context.Context, conn *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS app_secrets (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			encryption_key BLOB NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			must_change_password INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1,
			is_admin INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE
		);`,
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id)
		);`,
		`CREATE TABLE IF NOT EXISTS group_roles (
			group_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			PRIMARY KEY (group_id, role_id)
		);`,
		`CREATE TABLE IF NOT EXISTS namespace_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role_id INTEGER NOT NULL,
			namespace TEXT NOT NULL,
			resource TEXT NOT NULL,
			action TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS ldap_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL DEFAULT 0,
			url TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 389,
			use_ssl INTEGER NOT NULL DEFAULT 0,
			start_tls INTEGER NOT NULL DEFAULT 0,
			ssl_skip_verify INTEGER NOT NULL DEFAULT 0,
			timeout_seconds INTEGER NOT NULL DEFAULT 10,
			bind_dn TEXT NOT NULL DEFAULT '',
			bind_password_enc BLOB NOT NULL DEFAULT '',
			user_base_dn TEXT NOT NULL DEFAULT '',
			user_base_dns TEXT NOT NULL DEFAULT '',
			user_filter TEXT NOT NULL DEFAULT '',
			username_attribute TEXT NOT NULL DEFAULT 'sAMAccountName'
		);`,
		`CREATE TABLE IF NOT EXISTS azure_ad_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL DEFAULT 0,
			tenant_id TEXT NOT NULL DEFAULT '',
			client_id TEXT NOT NULL DEFAULT '',
			client_secret_enc BLOB NOT NULL DEFAULT '',
			redirect_url TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS session_settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			session_minutes INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS kube_credentials (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			method TEXT NOT NULL DEFAULT '',
			kubeconfig_enc BLOB NOT NULL DEFAULT '',
			token_enc BLOB NOT NULL DEFAULT '',
			server TEXT NOT NULL DEFAULT '',
			ca_cert_enc BLOB NOT NULL DEFAULT '',
			active INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			user TEXT NOT NULL,
			action TEXT NOT NULL,
			namespace TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_name TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS clusters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			kubeconfig_enc BLOB NOT NULL DEFAULT '',
			token_enc BLOB NOT NULL DEFAULT '',
			server TEXT NOT NULL DEFAULT '',
			ca_cert_enc BLOB NOT NULL DEFAULT '',
			is_active INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		// session_tokens tracks every JWT this backend has issued, keyed by the
		// jti claim. AuthMiddleware looks up the row to enforce admin-driven
		// revocation; the JWT itself is still the primary auth artifact so that
		// a DB blip can only degrade revocation, not log everyone out.
		`CREATE TABLE IF NOT EXISTS session_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			jti TEXT NOT NULL UNIQUE,
			user_id INTEGER NOT NULL,
			issued_at DATETIME NOT NULL,
			last_used_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME NULL,
			ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_session_tokens_user ON session_tokens (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_session_tokens_expires ON session_tokens (expires_at)`,
		// Pod exec session recordings (asciicast v2 files on disk). ended_at
		// stays NULL while the session is open; startup recovery closes rows
		// left open by a crash.
		`CREATE TABLE IF NOT EXISTS session_recordings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL UNIQUE,
			user TEXT NOT NULL,
			cluster TEXT NOT NULL DEFAULT '',
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			container TEXT NOT NULL DEFAULT '',
			started_at DATETIME NOT NULL,
			ended_at DATETIME NULL,
			size_bytes INTEGER NOT NULL DEFAULT 0,
			truncated INTEGER NOT NULL DEFAULT 0,
			request_id TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_session_recordings_started ON session_recordings (started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_session_recordings_user ON session_recordings (user)`,
		// Seeded from SESSION_RECORDING_* env on first boot by the recording
		// manager; the admin UI owns it afterwards.
		`CREATE TABLE IF NOT EXISTS recording_settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL DEFAULT 1,
			retention_days INTEGER NOT NULL DEFAULT 30,
			max_session_mb INTEGER NOT NULL DEFAULT 10,
			max_total_mb INTEGER NOT NULL DEFAULT 2048,
			min_free_mb INTEGER NOT NULL DEFAULT 512,
			disk_policy TEXT NOT NULL DEFAULT 'evict_oldest'
		);`,
	}

	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO ldap_config (id, enabled) VALUES (1, 0);`); err != nil {
		return fmt.Errorf("seed ldap config: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO azure_ad_config (id, enabled) VALUES (1, 0);`); err != nil {
		return fmt.Errorf("seed azure ad config: %w", err)
	}

	alterStatements := []string{
		// Multi-cluster phase 2: scope each permission to a cluster. NULL means
		// "all clusters" so pre-existing rows keep working unchanged.
		`ALTER TABLE namespace_permissions ADD COLUMN cluster_id INTEGER NULL`,
		`ALTER TABLE ldap_config ADD COLUMN host TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ldap_config ADD COLUMN port INTEGER NOT NULL DEFAULT 389`,
		`ALTER TABLE ldap_config ADD COLUMN use_ssl INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN start_tls INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN ssl_skip_verify INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 10`,
		`ALTER TABLE ldap_config ADD COLUMN user_base_dns TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ldap_config ADD COLUMN username_attribute TEXT NOT NULL DEFAULT 'sAMAccountName'`,
		// 2.13.0: per-user cluster selection, user auth source, audit cluster.
		`ALTER TABLE users ADD COLUMN active_cluster_id INTEGER NULL`,
		`ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local'`,
		`ALTER TABLE audit_logs ADD COLUMN cluster TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range alterStatements {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			// Ignore duplicate column errors for existing databases.
			continue
		}
	}

	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO session_settings (id, session_minutes) VALUES (1, 60);`); err != nil {
		return fmt.Errorf("seed session settings: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO kube_credentials (id, active) VALUES (1, 0);`); err != nil {
		return fmt.Errorf("seed kube credentials: %w", err)
	}

	// Multi-cluster migration: if someone had configured the legacy single
	// kube_credentials row and no cluster rows exist, copy that row into a
	// cluster called "default" so the switcher never comes up empty.
	var hasClusters int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM clusters`).Scan(&hasClusters); err != nil {
		return fmt.Errorf("count clusters: %w", err)
	}
	if hasClusters == 0 {
		var method, server string
		var kubeconfig, token, ca []byte
		var active int
		err := conn.QueryRowContext(ctx,
			`SELECT method, kubeconfig_enc, token_enc, server, ca_cert_enc, active FROM kube_credentials WHERE id = 1`,
		).Scan(&method, &kubeconfig, &token, &server, &ca, &active)
		if err == nil && (method != "" || active != 0) {
			_, _ = conn.ExecContext(ctx,
				`INSERT INTO clusters (name, description, method, kubeconfig_enc, token_enc, server, ca_cert_enc, is_active)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				"default", "Migrated from legacy single-cluster config.",
				method, kubeconfig, token, server, ca, 1,
			)
		}
	}

	return nil
}
