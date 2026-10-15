package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

func open(t *testing.T, path string) (*sql.DB, *store.Store) {
	t.Helper()
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	return database.Conn, st
}

// A database created by an old release (before clusters, auth sources,
// audit clusters, …) must open cleanly, gain the new columns with sane
// defaults and keep its rows.
func TestUpgradeFromLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1, is_admin INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)`,
		`CREATE TABLE audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL, user TEXT NOT NULL,
			action TEXT NOT NULL, namespace TEXT NOT NULL, resource_type TEXT NOT NULL, resource_name TEXT NOT NULL)`,
		`CREATE TABLE namespace_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, role_id INTEGER NOT NULL,
			namespace TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL)`,
		`CREATE TABLE ldap_config (id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0,
			url TEXT NOT NULL DEFAULT '', bind_dn TEXT NOT NULL DEFAULT '', bind_password_enc BLOB NOT NULL DEFAULT '',
			user_base_dn TEXT NOT NULL DEFAULT '', user_filter TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO users (username, password_hash, must_change_password, is_active, is_admin, created_at)
			VALUES ('olduser', 'hash', 0, 1, 1, '2025-01-01 00:00:00')`,
		`INSERT INTO audit_logs (timestamp, user, action, namespace, resource_type, resource_name)
			VALUES ('2025-01-01 00:00:00', 'olduser', 'login', '-', 'auth', 'ok')`,
		`INSERT INTO namespace_permissions (role_id, namespace, resource, action) VALUES (1, 'team-a', 'pods', 'list')`,
		`INSERT INTO ldap_config (id, enabled, url) VALUES (1, 1, 'ldap://dc:389')`,
	} {
		if _, err := legacy.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	legacy.Close()

	conn, st := open(t, path)
	defer conn.Close()
	ctx := context.Background()

	u, err := st.GetUserByUsername(ctx, "olduser")
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin || u.AuthSource != models.AuthSourceLocal || u.ActiveClusterID != 0 {
		t.Fatalf("migrated user = %+v", u)
	}
	logs, err := st.ListAuditLogs(ctx, 10, 0, "", "", "", nil, nil)
	if err != nil || len(logs) != 1 || logs[0].Cluster != "" || logs[0].User != "olduser" {
		t.Fatalf("migrated audit = %+v, %v", logs, err)
	}
	perms, err := st.ListNamespacePermissions(ctx, 1)
	if err != nil || len(perms) != 1 || perms[0].ClusterID != 0 {
		t.Fatalf("migrated permissions = %+v, %v", perms, err)
	}
	ldap, err := st.GetLDAPConfig(ctx)
	if err != nil || !ldap.Enabled || ldap.URL != "ldap://dc:389" || ldap.Port != 389 || ldap.UsernameAttribute != "sAMAccountName" {
		t.Fatalf("migrated ldap = %+v, %v", ldap, err)
	}
}

// Re-running migrations (every start) must be a no-op.
func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	conn, st := open(t, path)
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	for i := 0; i < 2; i++ {
		conn, st = open(t, path)
		users, err := st.ListUsers(ctx)
		if err != nil || len(users) != 1 {
			t.Fatalf("reopen %d: users = %+v, %v", i, users, err)
		}
		var rows int
		_ = conn.QueryRow(`SELECT COUNT(*) FROM session_settings`).Scan(&rows)
		if rows != 1 {
			t.Fatalf("session_settings seeded %d times", rows)
		}
		conn.Close()
	}
}

// Installs from before multi-cluster kept one cluster in kube_credentials; on
// upgrade it becomes the active "default" cluster with its credentials intact.
func TestLegacySingleClusterMigratesToClustersTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	conn, st := open(t, path)
	ctx := context.Background()
	if err := st.UpdateKubeCredentials(ctx, models.KubeCredentials{
		Method: "token", Server: "https://legacy:6443", Token: []byte("legacy-token"), Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	conn, st = open(t, path)
	defer conn.Close()
	c, err := st.GetActiveCluster(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "default" || c.Credentials.Server != "https://legacy:6443" || string(c.Credentials.Token) != "legacy-token" {
		t.Fatalf("migrated cluster = %+v", c)
	}
}

func TestClusterCredentialsAreEncryptedAtRest(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	defer conn.Close()
	ctx := context.Background()
	id, err := st.CreateCluster(ctx, "prod", "", models.KubeCredentials{
		Method: "token", Server: "https://prod:6443", Token: []byte("super-secret-token"), CACert: []byte("CA-PEM"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := conn.QueryRow(`SELECT token_enc || ca_cert_enc FROM clusters WHERE id = ?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "super-secret-token") || strings.Contains(raw, "CA-PEM") {
		t.Fatal("cluster credentials stored in plain text")
	}
	c, err := st.GetCluster(ctx, id)
	if err != nil || string(c.Credentials.Token) != "super-secret-token" || string(c.Credentials.CACert) != "CA-PEM" {
		t.Fatalf("round trip = %+v, %v", c, err)
	}

	// Activation is exclusive and the active (default) cluster can't be deleted.
	id2, _ := st.CreateCluster(ctx, "dev", "", models.KubeCredentials{Method: "token", Server: "https://dev", Token: []byte("t")})
	_ = st.ActivateCluster(ctx, id)
	_ = st.ActivateCluster(ctx, id2)
	if c, _ := st.GetActiveCluster(ctx); c.ID != id2 {
		t.Fatalf("active = %d, want %d", c.ID, id2)
	}
	if err := st.DeleteCluster(ctx, id2); err == nil {
		t.Fatal("deleting the active cluster should fail")
	}
	if err := st.DeleteCluster(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestPermissionsJoinThroughGroupsAndRoles(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	defer conn.Close()
	ctx := context.Background()
	uid, _ := st.CreateUser(ctx, "bob", "hash")
	other, _ := st.CreateUser(ctx, "eve", "hash")
	r1, _ := st.CreateRole(ctx, "viewer", "")
	r2, _ := st.CreateRole(ctx, "prod-exec", "")
	_ = st.AddNamespacePermission(ctx, r1, 0, "team-a", "pods", "list")
	_ = st.AddNamespacePermission(ctx, r2, 7, "team-a", "pods", "exec")
	g, _ := st.CreateGroup(ctx, "devs")
	_ = st.SetGroupRoles(ctx, g, []int{r1, r2})
	_ = st.SetUserGroups(ctx, uid, []int{g})

	perms, err := st.ListPermissionsByUser(ctx, uid)
	if err != nil || len(perms) != 2 {
		t.Fatalf("bob perms = %+v, %v", perms, err)
	}
	clusters := map[string]int{}
	for _, p := range perms {
		clusters[p.Action] = p.ClusterID
	}
	if clusters["list"] != 0 || clusters["exec"] != 7 {
		t.Fatalf("cluster scoping lost: %+v", clusters)
	}
	if perms, _ := st.ListPermissionsByUser(ctx, other); len(perms) != 0 {
		t.Fatalf("eve has no groups but got %+v", perms)
	}
}

func TestSessionsRevokeAndExpire(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	defer conn.Close()
	ctx := context.Background()
	uid, _ := st.CreateUser(ctx, "bob", "hash")
	now := time.Now().UTC()
	_ = st.CreateSession(ctx, "live", uid, now, now.Add(time.Hour), "1.2.3.4", "ua")
	_ = st.CreateSession(ctx, "old", uid, now.Add(-2*time.Hour), now.Add(-time.Hour), "1.2.3.4", "ua")

	if s, _ := st.LookupSession(ctx, "live"); !s.Found || s.Revoked || s.Expired {
		t.Fatalf("live = %+v", s)
	}
	if s, _ := st.LookupSession(ctx, "old"); !s.Expired {
		t.Fatalf("old should be expired: %+v", s)
	}
	if s, _ := st.LookupSession(ctx, "unknown"); s.Found {
		t.Fatal("unknown jti should not be found")
	}
	_ = st.RevokeAllForUser(ctx, uid)
	if s, _ := st.LookupSession(ctx, "live"); !s.Revoked {
		t.Fatalf("live should be revoked: %+v", s)
	}
}

func TestAuditFiltersAndCluster(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	defer conn.Close()
	ctx := context.Background()
	base := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	for i, e := range []models.AuditLog{
		{User: "alice", Action: "deployment.restart.success", Namespace: "team-a", ResourceType: "deployment", ResourceName: "api", Cluster: "prod"},
		{User: "bob", Action: "pod.exec.start", Namespace: "team-b", ResourceType: "pod", ResourceName: "web", Cluster: "dev"},
		{User: "alice", Action: "login.failed", Namespace: "-", ResourceType: "auth", ResourceName: "bad"},
	} {
		e.Timestamp = base.Add(time.Duration(i) * time.Hour)
		if err := st.AddAuditLog(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if logs, _ := st.ListAuditLogs(ctx, 10, 0, "alice", "", "", nil, nil); len(logs) != 2 {
		t.Fatalf("user filter: %d", len(logs))
	}
	if logs, _ := st.ListAuditLogs(ctx, 10, 0, "", "exec", "", nil, nil); len(logs) != 1 || logs[0].Cluster != "dev" {
		t.Fatalf("action filter: %+v", logs)
	}
	from := base.Add(30 * time.Minute)
	if n, _ := st.CountAuditLogs(ctx, "", "", "", &from, nil); n != 2 {
		t.Fatalf("time filter count = %d", n)
	}
	if err := st.PurgeAuditLogs(ctx, base.Add(90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountAuditLogs(ctx, "", "", "", nil, nil); n != 1 {
		t.Fatalf("after purge = %d", n)
	}
}

func TestAuditFilterModesAndFacets(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	defer conn.Close()
	ctx := context.Background()
	for _, e := range []models.AuditLog{
		{User: "alice", Action: "pod.exec", Verb: "exec", Outcome: "success", Namespace: "team-a", ResourceType: "pod", Cluster: "prod",
			Details: map[string]any{"phase": "start"}},
		{User: "alice", Action: "pod.exec", Verb: "exec", Outcome: "success", Namespace: "team-a", ResourceType: "pod", Cluster: "prod",
			Details: map[string]any{"phase": "end", "exit_code": 0}},
		{User: "bob", Action: "pod.exec", Verb: "exec", Outcome: "denied", Namespace: "team-b", ResourceType: "pod", Cluster: "dev"},
		{User: "bob", Action: "secret.reveal", Verb: "reveal", Outcome: "denied", Namespace: "team-b", ResourceType: "secret", Cluster: "dev"},
		{User: "carol", Action: "secret.reveal", Verb: "reveal", Outcome: "success", Namespace: "team-a", ResourceType: "secret", Cluster: "prod"},
		{User: "carol", Action: "deployment.scale", Verb: "scale", Outcome: "rate_limited", Namespace: "team-a", ResourceType: "deployment", Cluster: "prod"},
		{User: "dave_x", Action: "user.login", Verb: "login", Outcome: "failed", Reason: "bad_password", ResourceType: "user"},
	} {
		e.Timestamp = time.Now().UTC()
		e.ResourceName = "x"
		if err := st.AddAuditLog(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	count := func(f store.AuditFilter) int {
		t.Helper()
		n, err := st.CountAuditLogsFiltered(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	cases := []struct {
		name string
		f    store.AuditFilter
		want int
	}{
		{"family", store.AuditFilter{Action: "pod.*"}, 3},
		{"exact", store.AuditFilter{Action: "pod.exec", ActionExact: true}, 3},
		{"exact needs the whole name", store.AuditFilter{Action: "pod.ex", ActionExact: true}, 0},
		{"contains", store.AuditFilter{Action: "reveal"}, 2},
		{"outcome", store.AuditFilter{Outcome: "denied"}, 2},
		{"outcome rate_limited", store.AuditFilter{Outcome: "rate_limited"}, 1},
		{"family + outcome", store.AuditFilter{Action: "secret.*", Outcome: "denied"}, 1},
		{"pre-2.17 action with outcome", store.AuditFilter{Action: "secret.reveal.denied"}, 1},
		{"verb", store.AuditFilter{Verb: "exec"}, 3},
		{"resource type", store.AuditFilter{ResourceType: "secret"}, 2},
		{"cluster", store.AuditFilter{Cluster: "dev"}, 2},
		// _ and % are literal, not LIKE wildcards.
		{"underscore literal", store.AuditFilter{User: "e_x"}, 1},
		{"underscore literal, no false match", store.AuditFilter{User: "v_x"}, 0},
		{"percent literal", store.AuditFilter{Action: "%"}, 0},
	}
	for _, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}

	logs, err := st.ListAuditLogsFiltered(ctx, 10, 0, store.AuditFilter{Verb: "exec", Outcome: "success"})
	if err != nil || len(logs) != 2 {
		t.Fatalf("logs = %v, %v", logs, err)
	}
	if logs[0].Details["phase"] != "end" || logs[0].Details["exit_code"] != float64(0) {
		t.Fatalf("details = %v", logs[0].Details)
	}

	f, err := st.AuditFacets(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.Actions, ",") != "deployment.scale,pod.exec,secret.reveal,user.login" {
		t.Fatalf("actions = %v", f.Actions)
	}
	if strings.Join(f.Users, ",") != "alice,bob,carol,dave_x" {
		t.Fatalf("users = %v", f.Users)
	}
	if strings.Join(f.Namespaces, ",") != "team-a,team-b" { // "" left out
		t.Fatalf("namespaces = %v", f.Namespaces)
	}
	if strings.Join(f.Verbs, ",") != "exec,login,reveal,scale" || strings.Join(f.Clusters, ",") != "dev,prod" ||
		strings.Join(f.ResourceTypes, ",") != "deployment,pod,secret,user" {
		t.Fatalf("facets = %+v", f)
	}
}

// last_login_at: existing accounts are backfilled once, when the column is
// added; accounts pre-created afterwards stay "never signed in" across
// restarts until their first sign-in.
func TestLastLoginBackfillAndUnclaimedAzure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1, is_admin INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)`,
		`INSERT INTO users (username, password_hash, created_at) VALUES ('old@corp.com', 'h', '2025-01-01 00:00:00')`,
	} {
		if _, err := legacy.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	legacy.Close()

	ctx := context.Background()
	conn, st := open(t, path)
	old, _ := st.GetUserByUsername(ctx, "old@corp.com")
	_ = st.SetUserAuthSource(ctx, old.ID, models.AuthSourceAzure)
	if _, err := st.FindUnclaimedAzureAccount(ctx, "old@corp.com"); err == nil {
		t.Fatal("an account from before the upgrade must not count as unclaimed")
	}
	newID, _ := st.CreateUser(ctx, "new@corp.com", "h")
	_ = st.SetUserAuthSource(ctx, newID, models.AuthSourceAzure)
	conn.Close()

	conn, st = open(t, path) // migrations run again: no second backfill
	defer conn.Close()
	if u, err := st.FindUnclaimedAzureAccount(ctx, "NEW@corp.com"); err != nil || u.ID != newID {
		t.Fatalf("unclaimed = %+v, %v", u, err)
	}
	if err := st.MarkLogin(ctx, newID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FindUnclaimedAzureAccount(ctx, "new@corp.com"); err == nil {
		t.Fatal("still unclaimed after a sign-in")
	}
}
