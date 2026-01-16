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
	}

	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO ldap_config (id, enabled) VALUES (1, 0);`); err != nil {
		return fmt.Errorf("seed ldap config: %w", err)
	}

	alterStatements := []string{
		`ALTER TABLE ldap_config ADD COLUMN host TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ldap_config ADD COLUMN port INTEGER NOT NULL DEFAULT 389`,
		`ALTER TABLE ldap_config ADD COLUMN use_ssl INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN start_tls INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN ssl_skip_verify INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 10`,
		`ALTER TABLE ldap_config ADD COLUMN user_base_dns TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ldap_config ADD COLUMN username_attribute TEXT NOT NULL DEFAULT 'sAMAccountName'`,
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

	return nil
}
