package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"k8s-dashboard/backend/internal/models"
	"strings"
)

type Store struct {
	conn *sql.DB
	key  []byte
}

func New(conn *sql.DB) (*Store, error) {
	key, err := ensureKey(context.Background(), conn)
	if err != nil {
		return nil, err
	}
	return &Store{conn: conn, key: key}, nil
}

func (s *Store) SigningKey() []byte {
	return s.key
}

func ensureKey(ctx context.Context, conn *sql.DB) ([]byte, error) {
	var existing []byte
	err := conn.QueryRowContext(ctx, `SELECT encryption_key FROM app_secrets WHERE id = 1`).Scan(&existing)
	if err == nil && len(existing) > 0 {
		return existing, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR REPLACE INTO app_secrets (id, encryption_key) VALUES (1, ?)`, key); err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}
	return key, nil
}

func (s *Store) EnsureDefaultAdmin(ctx context.Context, passwordHash string) error {
	var count int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("check users: %w", err)
	}
	if count > 0 {
		return nil
	}
	_, err := s.conn.ExecContext(ctx, `INSERT INTO users (username, password_hash, must_change_password, is_active, is_admin, created_at) VALUES (?, ?, 1, 1, 1, ?)`, "admin", passwordHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("create default admin: %w", err)
	}
	return nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT id, username, password_hash, must_change_password, is_active, is_admin, created_at FROM users WHERE username = ?`, username)
	var user models.User
	var mustChange int
	var isActive int
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &mustChange, &isActive, &isAdmin, &user.CreatedAt); err != nil {
		return nil, err
	}
	user.MustChangePassword = mustChange == 1
	user.IsActive = isActive == 1
	user.IsAdmin = isAdmin == 1
	return &user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int) (*models.User, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT id, username, password_hash, must_change_password, is_active, is_admin, created_at FROM users WHERE id = ?`, id)
	var user models.User
	var mustChange int
	var isActive int
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &mustChange, &isActive, &isAdmin, &user.CreatedAt); err != nil {
		return nil, err
	}
	user.MustChangePassword = mustChange == 1
	user.IsActive = isActive == 1
	user.IsAdmin = isAdmin == 1
	return &user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, username, must_change_password, is_active, is_admin, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		var user models.User
		var mustChange int
		var isActive int
		var isAdmin int
		if err := rows.Scan(&user.ID, &user.Username, &mustChange, &isActive, &isAdmin, &user.CreatedAt); err != nil {
			return nil, err
		}
		user.MustChangePassword = mustChange == 1
		user.IsActive = isActive == 1
		user.IsAdmin = isAdmin == 1
		users = append(users, user)
	}
	return users, nil
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (int, error) {
	result, err := s.conn.ExecContext(ctx, `INSERT INTO users (username, password_hash, must_change_password, is_active, is_admin, created_at) VALUES (?, ?, 0, 1, 0, ?)`, username, passwordHash, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	return int(id), err
}

func (s *Store) UpdateUser(ctx context.Context, user models.User) error {
	mustChange := 0
	if user.MustChangePassword {
		mustChange = 1
	}
	isActive := 0
	if user.IsActive {
		isActive = 1
	}
	isAdmin := 0
	if user.IsAdmin {
		isAdmin = 1
	}
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET username = ?, must_change_password = ?, is_active = ?, is_admin = ? WHERE id = ?`, user.Username, mustChange, isActive, isAdmin, user.ID)
	return err
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID int, passwordHash string, mustChange bool) error {
	flag := 0
	if mustChange {
		flag = 1
	}
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?`, passwordHash, flag, userID)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Store) ListGroups(ctx context.Context) ([]models.Group, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, name FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []models.Group
	for rows.Next() {
		var group models.Group
		if err := rows.Scan(&group.ID, &group.Name); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (s *Store) CreateGroup(ctx context.Context, name string) (int, error) {
	result, err := s.conn.ExecContext(ctx, `INSERT INTO groups (name) VALUES (?)`, name)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	return int(id), err
}

func (s *Store) UpdateGroup(ctx context.Context, id int, name string) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE groups SET name = ? WHERE id = ?`, name, id)
	return err
}

func (s *Store) DeleteGroup(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	return err
}

func (s *Store) ListRoles(ctx context.Context) ([]models.Role, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, name, description FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []models.Role
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (s *Store) CreateRole(ctx context.Context, name, description string) (int, error) {
	result, err := s.conn.ExecContext(ctx, `INSERT INTO roles (name, description) VALUES (?, ?)`, name, description)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	return int(id), err
}

func (s *Store) UpdateRole(ctx context.Context, role models.Role) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE roles SET name = ?, description = ? WHERE id = ?`, role.Name, role.Description, role.ID)
	return err
}

func (s *Store) DeleteRole(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id)
	return err
}

func (s *Store) ListNamespacePermissions(ctx context.Context, roleID int) ([]models.NamespacePermission, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, role_id, namespace, resource, action FROM namespace_permissions WHERE role_id = ?`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var permissions []models.NamespacePermission
	for rows.Next() {
		var perm models.NamespacePermission
		if err := rows.Scan(&perm.ID, &perm.RoleID, &perm.Namespace, &perm.Resource, &perm.Action); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, nil
}

func (s *Store) AddNamespacePermission(ctx context.Context, roleID int, namespace, resource, action string) error {
	_, err := s.conn.ExecContext(ctx, `INSERT INTO namespace_permissions (role_id, namespace, resource, action) VALUES (?, ?, ?, ?)`, roleID, namespace, resource, action)
	return err
}

func (s *Store) DeleteNamespacePermission(ctx context.Context, id int) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM namespace_permissions WHERE id = ?`, id)
	return err
}

func (s *Store) SetUserGroups(ctx context.Context, userID int, groupIDs []int) error {
	if _, err := s.conn.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if _, err := s.conn.ExecContext(ctx, `INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)`, userID, groupID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetUserGroups(ctx context.Context, userID int) ([]int, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT group_id FROM user_groups WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Store) SetGroupRoles(ctx context.Context, groupID int, roleIDs []int) error {
	if _, err := s.conn.ExecContext(ctx, `DELETE FROM group_roles WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if _, err := s.conn.ExecContext(ctx, `INSERT INTO group_roles (group_id, role_id) VALUES (?, ?)`, groupID, roleID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetGroupRoles(ctx context.Context, groupID int) ([]int, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT role_id FROM group_roles WHERE group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Store) ListGroupRoles(ctx context.Context, groupID int) ([]int, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT role_id FROM group_roles WHERE group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Store) ListUserGroups(ctx context.Context, userID int) ([]int, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT group_id FROM user_groups WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Store) GetLDAPConfig(ctx context.Context) (models.LDAPConfig, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT enabled, url, host, port, use_ssl, start_tls, ssl_skip_verify, timeout_seconds, bind_dn, bind_password_enc, user_base_dn, user_base_dns, user_filter, username_attribute FROM ldap_config WHERE id = 1`)
	var enabled int
	var useSSL int
	var startTLS int
	var skipVerify int
	var encPassword string
	var baseDNs string
	var cfg models.LDAPConfig
	if err := row.Scan(
		&enabled,
		&cfg.URL,
		&cfg.Host,
		&cfg.Port,
		&useSSL,
		&startTLS,
		&skipVerify,
		&cfg.TimeoutSeconds,
		&cfg.BindDN,
		&encPassword,
		&cfg.UserBaseDN,
		&baseDNs,
		&cfg.UserFilter,
		&cfg.UsernameAttribute,
	); err != nil {
		return cfg, err
	}
	cfg.Enabled = enabled == 1
	cfg.UseSSL = useSSL == 1
	cfg.StartTLS = startTLS == 1
	cfg.SkipVerify = skipVerify == 1
	cfg.PasswordConfigured = encPassword != ""
	password, err := decrypt(s.key, encPassword)
	if err != nil {
		return cfg, err
	}
	cfg.BindPassword = password
	if baseDNs != "" {
		cfg.UserBaseDNs = strings.Split(baseDNs, ",")
	}
	return cfg, nil
}

func (s *Store) UpdateLDAPConfig(ctx context.Context, cfg models.LDAPConfig) error {
	encPassword := ""
	if cfg.BindPassword != "" {
		encrypted, err := encrypt(s.key, cfg.BindPassword)
		if err != nil {
			return err
		}
		encPassword = encrypted
	} else if cfg.PasswordConfigured {
		if err := s.conn.QueryRowContext(ctx, `SELECT bind_password_enc FROM ldap_config WHERE id = 1`).Scan(&encPassword); err != nil {
			return err
		}
	}
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	useSSL := 0
	if cfg.UseSSL {
		useSSL = 1
	}
	startTLS := 0
	if cfg.StartTLS {
		startTLS = 1
	}
	skipVerify := 0
	if cfg.SkipVerify {
		skipVerify = 1
	}
	baseDNs := strings.Join(cfg.UserBaseDNs, ",")
	_, err := s.conn.ExecContext(ctx, `
		UPDATE ldap_config
		SET enabled = ?, url = ?, host = ?, port = ?, use_ssl = ?, start_tls = ?, ssl_skip_verify = ?, timeout_seconds = ?,
		    bind_dn = ?, bind_password_enc = ?, user_base_dn = ?, user_base_dns = ?, user_filter = ?, username_attribute = ?
		WHERE id = 1`,
		enabled,
		cfg.URL,
		cfg.Host,
		cfg.Port,
		useSSL,
		startTLS,
		skipVerify,
		cfg.TimeoutSeconds,
		cfg.BindDN,
		encPassword,
		cfg.UserBaseDN,
		baseDNs,
		cfg.UserFilter,
		cfg.UsernameAttribute,
	)
	return err
}

func (s *Store) GetSessionSettings(ctx context.Context) (models.SessionSettings, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT session_minutes FROM session_settings WHERE id = 1`)
	var settings models.SessionSettings
	if err := row.Scan(&settings.SessionMinutes); err != nil {
		return settings, err
	}
	return settings, nil
}

func (s *Store) UpdateSessionSettings(ctx context.Context, settings models.SessionSettings) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE session_settings SET session_minutes = ? WHERE id = 1`, settings.SessionMinutes)
	return err
}

func (s *Store) GetKubeCredentials(ctx context.Context) (models.KubeCredentials, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT method, kubeconfig_enc, token_enc, server, ca_cert_enc, active FROM kube_credentials WHERE id = 1`)
	var creds models.KubeCredentials
	var encKubeconfig string
	var encToken string
	var encCA string
	var active int
	if err := row.Scan(&creds.Method, &encKubeconfig, &encToken, &creds.Server, &encCA, &active); err != nil {
		return creds, err
	}
	creds.Active = active == 1
	kubeconfig, err := decrypt(s.key, encKubeconfig)
	if err != nil {
		return creds, err
	}
	token, err := decrypt(s.key, encToken)
	if err != nil {
		return creds, err
	}
	ca, err := decrypt(s.key, encCA)
	if err != nil {
		return creds, err
	}
	creds.Kubeconfig = []byte(kubeconfig)
	creds.Token = []byte(token)
	creds.CACert = []byte(ca)
	return creds, nil
}

func (s *Store) UpdateKubeCredentials(ctx context.Context, creds models.KubeCredentials) error {
	encKubeconfig, err := encrypt(s.key, string(creds.Kubeconfig))
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
	active := 0
	if creds.Active {
		active = 1
	}
	_, err = s.conn.ExecContext(ctx, `UPDATE kube_credentials SET method = ?, kubeconfig_enc = ?, token_enc = ?, server = ?, ca_cert_enc = ?, active = ? WHERE id = 1`, creds.Method, encKubeconfig, encToken, creds.Server, encCA, active)
	return err
}

func (s *Store) AddAuditLog(ctx context.Context, entry models.AuditLog) error {
	_, err := s.conn.ExecContext(ctx, `INSERT INTO audit_logs (timestamp, user, action, namespace, resource_type, resource_name) VALUES (?, ?, ?, ?, ?, ?)`, entry.Timestamp, entry.User, entry.Action, entry.Namespace, entry.ResourceType, entry.ResourceName)
	return err
}

func (s *Store) ListAuditLogs(ctx context.Context, limit, offset int, userFilter, actionFilter, namespaceFilter string, startTime, endTime *time.Time) ([]models.AuditLog, error) {
	query := `SELECT id, timestamp, user, action, namespace, resource_type, resource_name FROM audit_logs`
	args := []interface{}{}
	conditions := []string{}
	if userFilter != "" {
		conditions = append(conditions, "user LIKE ?")
		args = append(args, "%"+userFilter+"%")
	}
	if actionFilter != "" {
		conditions = append(conditions, "action LIKE ?")
		args = append(args, "%"+actionFilter+"%")
	}
	if namespaceFilter != "" {
		conditions = append(conditions, "namespace LIKE ?")
		args = append(args, "%"+namespaceFilter+"%")
	}
	if startTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *startTime)
	}
	if endTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *endTime)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []models.AuditLog
	for rows.Next() {
		var entry models.AuditLog
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.User, &entry.Action, &entry.Namespace, &entry.ResourceType, &entry.ResourceName); err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	return logs, nil
}

func (s *Store) CountAuditLogs(ctx context.Context, userFilter, actionFilter, namespaceFilter string, startTime, endTime *time.Time) (int, error) {
	query := `SELECT COUNT(1) FROM audit_logs`
	args := []interface{}{}
	conditions := []string{}
	if userFilter != "" {
		conditions = append(conditions, "user LIKE ?")
		args = append(args, "%"+userFilter+"%")
	}
	if actionFilter != "" {
		conditions = append(conditions, "action LIKE ?")
		args = append(args, "%"+actionFilter+"%")
	}
	if namespaceFilter != "" {
		conditions = append(conditions, "namespace LIKE ?")
		args = append(args, "%"+namespaceFilter+"%")
	}
	if startTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *startTime)
	}
	if endTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *endTime)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	var count int
	if err := s.conn.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) PurgeAuditLogs(ctx context.Context, olderThan time.Time) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM audit_logs WHERE timestamp < ?`, olderThan)
	return err
}

func (s *Store) ListPermissionsByUser(ctx context.Context, userID int) ([]models.NamespacePermission, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT np.id, np.role_id, np.namespace, np.resource, np.action
		FROM namespace_permissions np
		JOIN group_roles gr ON np.role_id = gr.role_id
		JOIN user_groups ug ON gr.group_id = ug.group_id
		WHERE ug.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var permissions []models.NamespacePermission
	for rows.Next() {
		var perm models.NamespacePermission
		if err := rows.Scan(&perm.ID, &perm.RoleID, &perm.Namespace, &perm.Resource, &perm.Action); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, nil
}
