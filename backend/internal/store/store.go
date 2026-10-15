package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"k8s-dashboard/backend/internal/models"
	"strconv"
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

// Ping verifies the underlying DB connection is responsive. Used by readyz.
func (s *Store) Ping(ctx context.Context) error {
	return s.conn.PingContext(ctx)
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
	row := s.conn.QueryRowContext(ctx, `SELECT id, username, password_hash, must_change_password, is_active, is_admin, created_at, auth_source, COALESCE(active_cluster_id, 0) FROM users WHERE username = ?`, username)
	var user models.User
	var mustChange int
	var isActive int
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &mustChange, &isActive, &isAdmin, &user.CreatedAt, &user.AuthSource, &user.ActiveClusterID); err != nil {
		return nil, err
	}
	user.MustChangePassword = mustChange == 1
	user.IsActive = isActive == 1
	user.IsAdmin = isAdmin == 1
	return &user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int) (*models.User, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT id, username, password_hash, must_change_password, is_active, is_admin, created_at, auth_source, COALESCE(active_cluster_id, 0) FROM users WHERE id = ?`, id)
	var user models.User
	var mustChange int
	var isActive int
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &mustChange, &isActive, &isAdmin, &user.CreatedAt, &user.AuthSource, &user.ActiveClusterID); err != nil {
		return nil, err
	}
	user.MustChangePassword = mustChange == 1
	user.IsActive = isActive == 1
	user.IsAdmin = isAdmin == 1
	return &user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, username, must_change_password, is_active, is_admin, created_at, auth_source, COALESCE(active_cluster_id, 0) FROM users ORDER BY username`)
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
		if err := rows.Scan(&user.ID, &user.Username, &mustChange, &isActive, &isAdmin, &user.CreatedAt, &user.AuthSource, &user.ActiveClusterID); err != nil {
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

// CountActiveAdmins returns how many users are flagged is_admin AND is_active.
// Used to block self-destruct scenarios where the last admin would lock
// everyone out of the system.
func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_active = 1`).Scan(&n)
	return n, err
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
	rows, err := s.conn.QueryContext(ctx, `
		SELECT np.id, np.role_id, COALESCE(np.cluster_id, 0),
		       COALESCE(c.name, ''),
		       np.namespace, np.resource, np.action
		FROM namespace_permissions np
		LEFT JOIN clusters c ON c.id = np.cluster_id
		WHERE np.role_id = ?
		ORDER BY np.cluster_id, np.namespace, np.resource, np.action`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var permissions []models.NamespacePermission
	for rows.Next() {
		var perm models.NamespacePermission
		if err := rows.Scan(&perm.ID, &perm.RoleID, &perm.ClusterID, &perm.ClusterName,
			&perm.Namespace, &perm.Resource, &perm.Action); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, nil
}

// AddNamespacePermission writes a row. clusterID == 0 is stored as NULL
// (meaning "all clusters").
func (s *Store) AddNamespacePermission(ctx context.Context, roleID, clusterID int, namespace, resource, action string) error {
	if clusterID <= 0 {
		_, err := s.conn.ExecContext(ctx,
			`INSERT INTO namespace_permissions (role_id, cluster_id, namespace, resource, action) VALUES (?, NULL, ?, ?, ?)`,
			roleID, namespace, resource, action)
		return err
	}
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO namespace_permissions (role_id, cluster_id, namespace, resource, action) VALUES (?, ?, ?, ?, ?)`,
		roleID, clusterID, namespace, resource, action)
	return err
}

// GetNamespacePermission returns one grant with its cluster name.
func (s *Store) GetNamespacePermission(ctx context.Context, id int) (*models.NamespacePermission, error) {
	var perm models.NamespacePermission
	err := s.conn.QueryRowContext(ctx, `
		SELECT np.id, np.role_id, COALESCE(np.cluster_id, 0), COALESCE(c.name, ''),
		       np.namespace, np.resource, np.action
		FROM namespace_permissions np
		LEFT JOIN clusters c ON c.id = np.cluster_id
		WHERE np.id = ?`, id).Scan(&perm.ID, &perm.RoleID, &perm.ClusterID, &perm.ClusterName,
		&perm.Namespace, &perm.Resource, &perm.Action)
	if err != nil {
		return nil, err
	}
	return &perm, nil
}

// ClusterIDByName returns the id of the cluster with this name, 0 if none.
func (s *Store) ClusterIDByName(ctx context.Context, name string) int {
	var id int
	_ = s.conn.QueryRowContext(ctx, `SELECT id FROM clusters WHERE name = ?`, name).Scan(&id)
	return id
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
	row := s.conn.QueryRowContext(ctx, `SELECT enabled, url, host, port, use_ssl, start_tls, ssl_skip_verify, timeout_seconds, bind_dn, bind_password_enc, user_base_dn, user_base_dns, user_filter, username_attribute, auto_provision, auto_provision_groups FROM ldap_config WHERE id = 1`)
	var enabled, autoProvision int
	var autoGroups string
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
		&autoProvision,
		&autoGroups,
	); err != nil {
		return cfg, err
	}
	cfg.Enabled = enabled == 1
	cfg.AutoProvision = autoProvision == 1
	cfg.AutoProvisionGroupIDs = []int{}
	for _, part := range strings.Split(autoGroups, ",") {
		if id, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			cfg.AutoProvisionGroupIDs = append(cfg.AutoProvisionGroupIDs, id)
		}
	}
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
	autoProvision := 0
	if cfg.AutoProvision {
		autoProvision = 1
	}
	groupParts := make([]string, 0, len(cfg.AutoProvisionGroupIDs))
	for _, id := range cfg.AutoProvisionGroupIDs {
		groupParts = append(groupParts, strconv.Itoa(id))
	}
	_, err := s.conn.ExecContext(ctx, `
		UPDATE ldap_config
		SET enabled = ?, url = ?, host = ?, port = ?, use_ssl = ?, start_tls = ?, ssl_skip_verify = ?, timeout_seconds = ?,
		    bind_dn = ?, bind_password_enc = ?, user_base_dn = ?, user_base_dns = ?, user_filter = ?, username_attribute = ?,
		    auto_provision = ?, auto_provision_groups = ?
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
		autoProvision,
		strings.Join(groupParts, ","),
	)
	return err
}

func (s *Store) GetAzureADConfig(ctx context.Context) (models.AzureADConfig, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT enabled, tenant_id, client_id, client_secret_enc, redirect_url FROM azure_ad_config WHERE id = 1`)
	var cfg models.AzureADConfig
	var enabled int
	var encSecret string
	if err := row.Scan(&enabled, &cfg.TenantID, &cfg.ClientID, &encSecret, &cfg.RedirectURL); err != nil {
		return cfg, err
	}
	cfg.Enabled = enabled == 1
	cfg.PasswordConfigured = encSecret != ""
	secret, err := decrypt(s.key, encSecret)
	if err != nil {
		return cfg, err
	}
	cfg.ClientSecret = secret
	return cfg, nil
}

func (s *Store) UpdateAzureADConfig(ctx context.Context, cfg models.AzureADConfig) error {
	encSecret := ""
	if cfg.ClientSecret != "" {
		encrypted, err := encrypt(s.key, cfg.ClientSecret)
		if err != nil {
			return err
		}
		encSecret = encrypted
	} else if cfg.PasswordConfigured {
		if err := s.conn.QueryRowContext(ctx, `SELECT client_secret_enc FROM azure_ad_config WHERE id = 1`).Scan(&encSecret); err != nil {
			return err
		}
	}

	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	_, err := s.conn.ExecContext(
		ctx,
		`UPDATE azure_ad_config SET enabled = ?, tenant_id = ?, client_id = ?, client_secret_enc = ?, redirect_url = ? WHERE id = 1`,
		enabled,
		cfg.TenantID,
		cfg.ClientID,
		encSecret,
		cfg.RedirectURL,
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
	details := ""
	if len(entry.Details) > 0 {
		b, err := json.Marshal(entry.Details)
		if err != nil {
			return err
		}
		details = string(b)
	}
	_, err := s.conn.ExecContext(ctx, `INSERT INTO audit_logs
		(timestamp, user, action, verb, outcome, reason, namespace, resource_type, resource_name,
		 cluster, cluster_id, details, request_id, source_ip, user_agent, auth_source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.User, entry.Action, entry.Verb, entry.Outcome, entry.Reason,
		entry.Namespace, entry.ResourceType, entry.ResourceName, entry.Cluster, entry.ClusterID,
		details, entry.RequestID, entry.SourceIP, entry.UserAgent, entry.AuthSource)
	return err
}

// AuditFilter selects audit entries. User, Namespace and ResourceName match
// anywhere in the field. Action: "family.*" matches every action starting
// with "family.", ActionExact matches exactly, anything else matches
// anywhere; an action ending in an outcome (deployment.restart.success, the
// pre-2.17 form) is split into action and outcome. Verb, Outcome,
// ResourceType and Cluster match exactly.
type AuditFilter struct {
	User         string
	Action       string
	ActionExact  bool
	Verb         string
	Outcome      string
	ResourceType string
	ResourceName string
	Cluster      string
	Namespace    string
	Start, End   *time.Time
}

// auditOutcomeSuffixes are the outcomes a pre-2.17 action ended in.
var auditOutcomeSuffixes = []string{"success", "denied", "failed", "rate_limited", "locked"}

// likeEscape makes s a literal inside a LIKE pattern (ESCAPE '\').
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (f AuditFilter) where() (string, []interface{}) {
	var conditions []string
	var args []interface{}
	contains := func(column, value string) {
		conditions = append(conditions, column+` LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(value)+"%")
	}
	equals := func(column, value string) {
		conditions = append(conditions, column+" = ?")
		args = append(args, value)
	}
	if f.User != "" {
		contains("user", f.User)
	}
	for _, o := range auditOutcomeSuffixes {
		if strings.HasSuffix(f.Action, "."+o) && f.Outcome == "" {
			f.Action, f.Outcome = strings.TrimSuffix(f.Action, "."+o), o
			break
		}
	}
	switch {
	case f.Action == "":
	case strings.HasSuffix(f.Action, ".*"):
		conditions = append(conditions, `action LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(strings.TrimSuffix(f.Action, "*"))+"%")
	case f.ActionExact:
		equals("action", f.Action)
	default:
		contains("action", f.Action)
	}
	if f.Verb != "" {
		equals("verb", f.Verb)
	}
	if f.Outcome != "" {
		equals("outcome", f.Outcome)
	}
	if f.ResourceType != "" {
		equals("resource_type", f.ResourceType)
	}
	if f.ResourceName != "" {
		contains("resource_name", f.ResourceName)
	}
	if f.Cluster != "" {
		equals("cluster", f.Cluster)
	}
	if f.Namespace != "" {
		contains("namespace", f.Namespace)
	}
	if f.Start != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *f.Start)
	}
	if f.End != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *f.End)
	}
	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) ListAuditLogs(ctx context.Context, limit, offset int, userFilter, actionFilter, namespaceFilter string, startTime, endTime *time.Time) ([]models.AuditLog, error) {
	return s.ListAuditLogsFiltered(ctx, limit, offset, AuditFilter{User: userFilter, Action: actionFilter, Namespace: namespaceFilter, Start: startTime, End: endTime})
}

const auditColumns = `id, timestamp, user, action, verb, outcome, reason, namespace, resource_type,
	resource_name, cluster, cluster_id, details, request_id, source_ip, user_agent, auth_source`

func (s *Store) ListAuditLogsFiltered(ctx context.Context, limit, offset int, f AuditFilter) ([]models.AuditLog, error) {
	where, args := f.where()
	query := `SELECT ` + auditColumns + ` FROM audit_logs` + where + ` ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []models.AuditLog
	for rows.Next() {
		var entry models.AuditLog
		var details string
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.User, &entry.Action, &entry.Verb,
			&entry.Outcome, &entry.Reason, &entry.Namespace, &entry.ResourceType, &entry.ResourceName,
			&entry.Cluster, &entry.ClusterID, &details, &entry.RequestID, &entry.SourceIP,
			&entry.UserAgent, &entry.AuthSource); err != nil {
			return nil, err
		}
		if details != "" {
			_ = json.Unmarshal([]byte(details), &entry.Details)
		}
		logs = append(logs, entry)
	}
	return logs, rows.Err()
}

func (s *Store) CountAuditLogs(ctx context.Context, userFilter, actionFilter, namespaceFilter string, startTime, endTime *time.Time) (int, error) {
	return s.CountAuditLogsFiltered(ctx, AuditFilter{User: userFilter, Action: actionFilter, Namespace: namespaceFilter, Start: startTime, End: endTime})
}

func (s *Store) CountAuditLogsFiltered(ctx context.Context, f AuditFilter) (int, error) {
	where, args := f.where()
	var count int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_logs`+where, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// AuditFacets are the distinct values found in the audit log, for the filter
// suggestions in Admin → Audit Logs.
type AuditFacets struct {
	Actions       []string `json:"actions"`
	Users         []string `json:"users"`
	Namespaces    []string `json:"namespaces"`
	Verbs         []string `json:"verbs"`
	ResourceTypes []string `json:"resourceTypes"`
	Clusters      []string `json:"clusters"`
}

// AuditFacets returns up to limit distinct values per column.
func (s *Store) AuditFacets(ctx context.Context, limit int) (AuditFacets, error) {
	distinct := func(column string) ([]string, error) {
		rows, err := s.conn.QueryContext(ctx,
			`SELECT DISTINCT `+column+` FROM audit_logs WHERE `+column+` NOT IN ('', '-') ORDER BY `+column+` LIMIT ?`, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, rows.Err()
	}
	var f AuditFacets
	for _, c := range []struct {
		column string
		dst    *[]string
	}{
		{"action", &f.Actions}, {"user", &f.Users}, {"namespace", &f.Namespaces},
		{"verb", &f.Verbs}, {"resource_type", &f.ResourceTypes}, {"cluster", &f.Clusters},
	} {
		v, err := distinct(c.column)
		if err != nil {
			return f, err
		}
		*c.dst = v
	}
	return f, nil
}

// LegacyAuditLogs returns rows written before 2.17 (no verb yet), at most
// limit of them.
func (s *Store) LegacyAuditLogs(ctx context.Context, limit int) ([]models.AuditLog, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT id, action, namespace, resource_type, resource_name FROM audit_logs WHERE verb = '' LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var e models.AuditLog
		if err := rows.Scan(&e.ID, &e.Action, &e.Namespace, &e.ResourceType, &e.ResourceName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpgradeAuditLogs rewrites the action, verb, outcome, namespace, resource
// type and name of the given rows in one transaction.
func (s *Store) UpgradeAuditLogs(ctx context.Context, entries []models.AuditLog) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `UPDATE audit_logs SET action = ?, verb = ?, outcome = ?,
		namespace = ?, resource_type = ?, resource_name = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.Action, e.Verb, e.Outcome, e.Namespace,
			e.ResourceType, e.ResourceName, e.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PurgeAuditLogs(ctx context.Context, olderThan time.Time) error {
	_, err := s.conn.ExecContext(ctx, `DELETE FROM audit_logs WHERE timestamp < ?`, olderThan)
	return err
}

func (s *Store) ListPermissionsByUser(ctx context.Context, userID int) ([]models.NamespacePermission, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT np.id, np.role_id, COALESCE(np.cluster_id, 0),
		       np.namespace, np.resource, np.action
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
		if err := rows.Scan(&perm.ID, &perm.RoleID, &perm.ClusterID,
			&perm.Namespace, &perm.Resource, &perm.Action); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, nil
}

// SetUserActiveCluster stores the cluster a user picked; 0 clears it (use the
// default cluster).
func (s *Store) SetUserActiveCluster(ctx context.Context, userID, clusterID int) error {
	var v any
	if clusterID > 0 {
		v = clusterID
	}
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET active_cluster_id = ? WHERE id = ?`, v, userID)
	return err
}

// MarkLogin records a successful sign-in.
func (s *Store) MarkLogin(ctx context.Context, userID int) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().UTC(), userID)
	return err
}

// FindUnclaimedAzureAccount returns the Azure AD account named name (any
// case) that an admin pre-created and nobody has signed in to yet.
func (s *Store) FindUnclaimedAzureAccount(ctx context.Context, name string) (*models.User, error) {
	var id int
	err := s.conn.QueryRowContext(ctx,
		`SELECT id FROM users WHERE lower(username) = lower(?) AND auth_source = 'azure' AND last_login_at IS NULL`,
		name).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, id)
}

// SetUserAuthSource records where a user signs in (local / ldap / azure).
func (s *Store) SetUserAuthSource(ctx context.Context, userID int, source string) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET auth_source = ? WHERE id = ?`, source, userID)
	return err
}
