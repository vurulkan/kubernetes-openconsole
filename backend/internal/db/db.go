package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB is the SQLite file. Conn is the one writing connection; Read is a small
// pool for reads that may take a while (audit lists, exports, facets) and for
// backups (VACUUM INTO), so they don't hold up writes. Never write through Read.
type DB struct {
	Conn *sql.DB
	Read *sql.DB
	path string
}

// BusyTimeoutMS is how long a statement waits for a lock held by another
// connection before it fails with SQLITE_BUSY. Tests lower it.
var BusyTimeoutMS = 5000

// dsn: WAL lets readers and the writer work at the same time; NORMAL sync is
// safe with WAL; foreign keys make ON DELETE CASCADE work; _txlock=immediate
// takes the write lock at BEGIN, so a transaction never fails half-way when
// it upgrades from reading to writing.
func dsn(path string) string {
	return path + fmt.Sprintf("?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)&_txlock=immediate", BusyTimeoutMS)
}

// Open opens (or creates) the database and brings its schema up to date.
func Open(dbPath string) (*DB, error) { return OpenWithBackup(dbPath, "") }

// OpenWithBackup is Open, and when the schema is about to change, it first
// copies the file into backupDir ("" = no copy) as app-<time>-pre-upgrade.db.
func OpenWithBackup(dbPath, backupDir string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	conn, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(5 * time.Minute)

	read, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open db: %w", err)
	}
	read.SetMaxOpenConns(4)
	read.SetConnMaxIdleTime(time.Minute)

	d := &DB{Conn: conn, Read: read, path: dbPath}
	ctx := context.Background()
	if backupDir != "" {
		if err := d.backupBeforeUpgrade(ctx, backupDir); err != nil {
			d.Close()
			return nil, err
		}
	}
	if err := migrate(ctx, conn); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Close closes both pools.
func (d *DB) Close() error {
	rerr := d.Read.Close()
	if err := d.Conn.Close(); err != nil {
		return err
	}
	return rerr
}

// BackupInto writes a consistent copy of the database to path (VACUUM INTO),
// readable by the server's user only: it holds every credential. It reads
// through the Read pool, so writes go on meanwhile.
func (d *DB) BackupInto(ctx context.Context, path string) error {
	if _, err := d.Read.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		os.Remove(path)
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		os.Remove(path)
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}

// backupBeforeUpgrade copies an existing database whose schema is older than
// this build, before migrate touches it.
func (d *DB) backupBeforeUpgrade(ctx context.Context, dir string) error {
	var tables, version int
	if err := d.Conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'`).Scan(&tables); err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if err := d.Conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if tables == 0 || version >= len(steps) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	path := filepath.Join(dir, BackupName(time.Now(), "pre-upgrade"))
	if err := d.BackupInto(ctx, path); err != nil {
		return fmt.Errorf("backup before upgrade (%s): %w", path, err)
	}
	return nil
}

// BackupName is app-<UTC time>[-<tag>].db; names sort by time.
func BackupName(t time.Time, tag string) string {
	name := "app-" + t.UTC().Format("20060102-150405")
	if tag != "" {
		name += "-" + tag
	}
	return name + ".db"
}

// migrate brings the schema up to date in one transaction: a failure leaves
// the file as it was and the server does not start. The CREATE / ALTER
// statements are idempotent and run on every start (an ALTER that fails for
// any reason but "duplicate column name" stops the migration); the steps
// below run once each, counted in PRAGMA user_version.
func migrate(ctx context.Context, conn *sql.DB) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := migrateTx(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: commit: %w", err)
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

func migrateTx(ctx context.Context, conn *sql.Tx) error {
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
			user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, group_id)
		);`,
		`CREATE TABLE IF NOT EXISTS group_roles (
			group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
			role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
			PRIMARY KEY (group_id, role_id)
		);`,
		`CREATE TABLE IF NOT EXISTS namespace_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
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
		// Dashboard saved views (namespace + tab + search + view mode) per
		// user; shared = visible to everyone. cluster_id = cluster the view
		// was saved on (NULL = none).
		`CREATE TABLE IF NOT EXISTS saved_views (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			cluster_id INTEGER NULL,
			namespace TEXT NOT NULL DEFAULT '',
			tab TEXT NOT NULL DEFAULT '',
			search TEXT NOT NULL DEFAULT '',
			view_mode TEXT NOT NULL DEFAULT 'card',
			shared INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			UNIQUE (user_id, name)
		);`,
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
		// 2.18.0: restart history, written by the pod informers. owner is
		// "Deployment/web", "StatefulSet/db", … (pre-release builds had a
		// container_terminations table keyed by deployment; it is left unused).
		`CREATE TABLE IF NOT EXISTS restart_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			cluster_id INTEGER NOT NULL,
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			container TEXT NOT NULL,
			owner TEXT NOT NULL DEFAULT '',
			exit_code INTEGER NOT NULL,
			signal INTEGER NOT NULL DEFAULT 0,
			reason TEXT NOT NULL DEFAULT '',
			first_at DATETIME NOT NULL,
			last_at DATETIME NOT NULL,
			count INTEGER NOT NULL DEFAULT 1
		);`,
		`CREATE INDEX IF NOT EXISTS idx_restart_history_pod ON restart_history (cluster_id, namespace, pod, container, last_at)`,
		`CREATE INDEX IF NOT EXISTS idx_restart_history_owner ON restart_history (cluster_id, namespace, owner, last_at)`,
		`CREATE INDEX IF NOT EXISTS idx_restart_history_last ON restart_history (last_at)`,
		// 2.22.0: API keys. hash = SHA-256 of the secret (never the secret);
		// the scope is clusters × namespaces (cluster_id 0 = every cluster,
		// namespace '' with all_namespaces), and the grants a key may use.
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			note TEXT NOT NULL DEFAULT '',
			prefix TEXT NOT NULL,
			hash TEXT NOT NULL UNIQUE,
			admin_scope INTEGER NOT NULL DEFAULT 0,
			all_namespaces INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			expires_at DATETIME NULL,
			last_used_at DATETIME NULL,
			last_used_ip TEXT NOT NULL DEFAULT '',
			revoked_at DATETIME NULL,
			UNIQUE (user_id, name)
		);`,
		`CREATE TABLE IF NOT EXISTS api_key_scopes (
			key_id INTEGER NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
			cluster_id INTEGER NOT NULL DEFAULT 0,
			namespace TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_scopes_key ON api_key_scopes (key_id)`,
		`CREATE TABLE IF NOT EXISTS api_key_permissions (
			key_id INTEGER NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
			resource TEXT NOT NULL,
			action TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_permissions_key ON api_key_permissions (key_id)`,
		// 2.24.0 (M30): one-time recovery codes of two-factor sign-in, SHA-256
		// of the code (never the code).
		`CREATE TABLE IF NOT EXISTS recovery_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			code_hash TEXT NOT NULL,
			used_at DATETIME NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id)`,
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
		// 2.16.0: optional LDAP account creation on first sign-in.
		`ALTER TABLE ldap_config ADD COLUMN auto_provision INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ldap_config ADD COLUMN auto_provision_groups TEXT NOT NULL DEFAULT ''`,
		// 2.17.0: structured audit events. Rows written before have verb ''
		// until audit.Logger.UpgradeLegacy fills it.
		`ALTER TABLE audit_logs ADD COLUMN verb TEXT NOT NULL DEFAULT ''`,
		// 2.18.0: per-cluster Prometheus settings (JSON, encrypted).
		`ALTER TABLE clusters ADD COLUMN prometheus_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN outcome TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN reason TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN cluster_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_logs ADD COLUMN details TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_logs ADD COLUMN auth_source TEXT NOT NULL DEFAULT ''`,
		// 2.22.0: the API key an action was taken with (0 / '' = web session).
		`ALTER TABLE audit_logs ADD COLUMN api_key_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_logs ADD COLUMN api_key_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE session_recordings ADD COLUMN api_key_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE session_recordings ADD COLUMN api_key_name TEXT NOT NULL DEFAULT ''`,
		// 2.22.0 (M15): API key policy. Every role, old or new, starts at safe
		// read-only; NULL override = by roles; expiry policy defaults to
		// today's behaviour (no limit, "never expires" allowed).
		`ALTER TABLE roles ADD COLUMN api_access TEXT NOT NULL DEFAULT 'safe_read'`,
		`ALTER TABLE users ADD COLUMN api_access_override TEXT NULL`,
		`ALTER TABLE session_settings ADD COLUMN api_key_max_days INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE session_settings ADD COLUMN api_key_allow_no_expiry INTEGER NOT NULL DEFAULT 1`,
		// 2.22.0 (M16): shell | command (one command over REST).
		`ALTER TABLE session_recordings ADD COLUMN mode TEXT NOT NULL DEFAULT 'shell'`,
		// 2.23.1 (M24): the Entra object id an Azure AD account belongs to
		// ('' = bound on its next Azure AD sign-in).
		`ALTER TABLE users ADD COLUMN azure_oid TEXT NOT NULL DEFAULT ''`,
		// 2.23.1 (M24): CA (PEM) the LDAP server's certificate is checked against.
		`ALTER TABLE ldap_config ADD COLUMN ca_cert TEXT NOT NULL DEFAULT ''`,
		// 2.24.0 (M30): two-factor sign-in. The TOTP secret (encrypted); on
		// once confirmed (totp_enabled_at); the last time step accepted, so a
		// code works once. Policy off by default: an upgrade changes nothing.
		`ALTER TABLE users ADD COLUMN totp_secret_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_enabled_at DATETIME NULL`,
		`ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE session_settings ADD COLUMN two_factor_policy TEXT NOT NULL DEFAULT 'off'`,
		`ALTER TABLE azure_ad_config ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0`,
		// 2.25.0 (M31): the admin's cluster order (numbered once in steps) and
		// the Azure AD directory search through Microsoft Graph (off by default).
		`ALTER TABLE clusters ADD COLUMN position INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE azure_ad_config ADD COLUMN graph_search INTEGER NOT NULL DEFAULT 0`,
	}
	for _, stmt := range alterStatements {
		if _, err := conn.ExecContext(ctx, stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("migrate %q: %w", stmt, err)
		}
	}
	// 2.15.0: last sign-in. When the column is new, every existing account
	// counts as having signed in, so only accounts pre-created from now on
	// are "never signed in" (which lets an Azure AD sign-in claim them by
	// e-mail, see handleAzureCallback).
	if _, err := conn.ExecContext(ctx, `ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL`); err == nil {
		if _, err := conn.ExecContext(ctx, `UPDATE users SET last_login_at = created_at`); err != nil {
			return fmt.Errorf("backfill last_login_at: %w", err)
		}
	} else if !isDuplicateColumn(err) {
		return fmt.Errorf("migrate last_login_at: %w", err)
	}

	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit_logs (outcome)`,
		// 2.23.1 (M26): the audit filters and their suggestion lists.
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_cluster ON audit_logs (cluster)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_namespace ON audit_logs (namespace)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_verb ON audit_logs (verb)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs (resource_type)`,
	} {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("audit indexes: %w", err)
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

	var version int
	if err := conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for v := version; v < len(steps); v++ {
		if err := steps[v](ctx, conn); err != nil {
			return fmt.Errorf("migrate step %d: %w", v+1, err)
		}
	}
	if version < len(steps) {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, len(steps))); err != nil {
			return fmt.Errorf("write schema version: %w", err)
		}
	}
	return nil
}

// steps run once each, in order; user_version = how many have run. Append
// only: never change or reorder a step that shipped.
var steps = []func(context.Context, *sql.Tx) error{
	// 1 (2.23.1): foreign keys for memberships and role permissions. The
	// tables had none, so deleting a user, group or role left rows behind and
	// any id was accepted. Rebuild them with ON DELETE CASCADE, keeping only
	// rows whose user / group / role still exists, and drop API key rows of
	// deleted users and keys.
	func(ctx context.Context, tx *sql.Tx) error {
		for _, stmt := range []string{
			`CREATE TABLE user_groups_v1 (
				user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
				PRIMARY KEY (user_id, group_id))`,
			`INSERT INTO user_groups_v1 SELECT user_id, group_id FROM user_groups
				WHERE user_id IN (SELECT id FROM users) AND group_id IN (SELECT id FROM groups)`,
			`DROP TABLE user_groups`,
			`ALTER TABLE user_groups_v1 RENAME TO user_groups`,
			`CREATE TABLE group_roles_v1 (
				group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
				role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
				PRIMARY KEY (group_id, role_id))`,
			`INSERT INTO group_roles_v1 SELECT group_id, role_id FROM group_roles
				WHERE group_id IN (SELECT id FROM groups) AND role_id IN (SELECT id FROM roles)`,
			`DROP TABLE group_roles`,
			`ALTER TABLE group_roles_v1 RENAME TO group_roles`,
			`CREATE TABLE namespace_permissions_v1 (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
				namespace TEXT NOT NULL,
				resource TEXT NOT NULL,
				action TEXT NOT NULL,
				cluster_id INTEGER NULL)`,
			`INSERT INTO namespace_permissions_v1 (id, role_id, namespace, resource, action, cluster_id)
				SELECT id, role_id, namespace, resource, action, cluster_id FROM namespace_permissions
				WHERE role_id IN (SELECT id FROM roles)`,
			`DROP TABLE namespace_permissions`,
			`ALTER TABLE namespace_permissions_v1 RENAME TO namespace_permissions`,
			`DELETE FROM api_keys WHERE user_id NOT IN (SELECT id FROM users)`,
			`DELETE FROM api_key_scopes WHERE key_id NOT IN (SELECT id FROM api_keys)`,
			`DELETE FROM api_key_permissions WHERE key_id NOT IN (SELECT id FROM api_keys)`,
		} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	},
	// 2.24.0: nothing to change by hand (two-factor columns are added above), but a
	// new user_version makes the upgrade copy the database first (backupBeforeUpgrade).
	func(context.Context, *sql.Tx) error { return nil },
	// 3 (2.25.0): clusters get the order they were shown in (default first,
	// then by name), so an upgrade doesn't reorder the switcher; the longest
	// API key lifetime is required now: 0 (no limit) becomes 365 days, more
	// than 3650 becomes 3650. Existing keys keep their expiry.
	func(ctx context.Context, tx *sql.Tx) error {
		for _, stmt := range []string{
			`UPDATE clusters SET position = (SELECT COUNT(*) FROM clusters c
				WHERE c.is_active > clusters.is_active
				OR (c.is_active = clusters.is_active AND (c.name < clusters.name OR (c.name = clusters.name AND c.id < clusters.id)))) + 1`,
			`UPDATE session_settings SET api_key_max_days = 365 WHERE api_key_max_days <= 0`,
			`UPDATE session_settings SET api_key_max_days = 3650 WHERE api_key_max_days > 3650`,
		} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	},
}
