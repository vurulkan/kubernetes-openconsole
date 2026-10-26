package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/recording"
	"k8s-dashboard/backend/internal/store"
)

// testEnv is a full Server (real SQLite store, real router + middleware) on
// top of client-go's fake clientset. Clusters 1 ("alpha", active) and 2
// ("beta") exist so cluster-scoped grants can be exercised.
type testEnv struct {
	t       *testing.T
	client  *fake.Clientset
	store   *store.Store
	server  *Server
	http    *httptest.Server
	alpha   *kube.Manager // the default cluster's connection
	alphaID int
}

const secretValue = "s3cr3t-db-password"

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tmp := t.TempDir()
	database, err := db.Open(filepath.Join(tmp, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAfterPendingWrites(database.Conn) })
	resetGlobalLimiters()
	// The fake clientset has no REST client for metrics.k8s.io.
	fetchNodeUsage = func(context.Context, kubernetes.Interface) (map[string]kube.Usage, error) {
		return nil, errors.New("no node metrics in tests")
	}
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	creds := models.KubeCredentials{Method: "token", Server: "https://example.invalid", Token: []byte("x")}
	alpha, err := st.CreateCluster(ctx, "alpha", "", creds)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := st.CreateCluster(ctx, "beta", "", creds)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateCluster(ctx, alpha); err != nil {
		t.Fatal(err)
	}

	immutable := true
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-c"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "team-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "team-b"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "db", Namespace: "team-a",
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"password":"` + base64.StdEncoding.EncodeToString([]byte(secretValue)) + `"}}`,
					"owner": "payments",
				},
			},
			Type:      corev1.SecretTypeOpaque,
			Immutable: &immutable,
			Data: map[string][]byte{
				"password": []byte(secretValue),
				"keystore": {0xff, 0xfe, 0x00, 0x01},
			},
		},
	)
	auditLogger := audit.New(st)
	rec, err := recording.New(ctx, st, auditLogger, filepath.Join(tmp, "recordings"), models.RecordingSettings{
		Enabled: true, RetentionDays: 30, MaxSessionMB: 10, MaxTotalMB: 100, DiskPolicy: models.RecordingPolicyEvictOldest,
	})
	if err != nil {
		t.Fatal(err)
	}
	clusters := kube.NewRegistry(nil)
	alphaMgr := kube.NewManagerWithClient(client)
	clusters.Put(alpha, alphaMgr)
	// beta is a different "cluster": its own objects, so tests can tell
	// which cluster a request actually reached.
	betaClient := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "beta-only"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "beta-pod", Namespace: "team-a"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"}},
	)
	clusters.Put(beta, kube.NewManagerWithClient(betaClient))
	srv := NewServer(st, auditLogger, clusters, rec, filepath.Join(tmp, "public"), tmp, "UTC")
	hs := httptest.NewServer(srv.Router())
	t.Cleanup(hs.Close)
	return &testEnv{t: t, client: client, store: st, server: srv, http: hs, alpha: alphaMgr, alphaID: alpha}
}

// user creates an account and returns a bearer token for it.
func (e *testEnv) user(name string, admin bool) (int, string) {
	e.t.Helper()
	ctx := context.Background()
	id, err := e.store.CreateUser(ctx, name, "unused-hash")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.UpdateUser(ctx, models.User{ID: id, Username: name, IsActive: true, IsAdmin: admin}); err != nil {
		e.t.Fatal(err)
	}
	return id, e.token(id, name)
}

func (e *testEnv) token(userID int, name string) string {
	e.t.Helper()
	jti := name + "-" + time.Now().Format("150405.000000000")
	tok, err := auth.GenerateToken(e.store.SigningKey(), userID, name, jti, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := e.store.CreateSession(context.Background(), jti, userID, now, now.Add(time.Hour), "127.0.0.1", "test"); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// grant gives the user a role with the given "cluster:ns:resource:action"
// tuples (cluster 0 = all clusters).
func (e *testEnv) grant(userID int, perms ...[4]any) {
	e.t.Helper()
	ctx := context.Background()
	suffix := time.Now().Format("150405.000000000")
	roleID, err := e.store.CreateRole(ctx, "role-"+suffix, "")
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range perms {
		if err := e.store.AddNamespacePermission(ctx, roleID, p[0].(int), p[1].(string), p[2].(string), p[3].(string)); err != nil {
			e.t.Fatal(err)
		}
	}
	groupID, err := e.store.CreateGroup(ctx, "group-"+suffix)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.SetGroupRoles(ctx, groupID, []int{roleID}); err != nil {
		e.t.Fatal(err)
	}
	groups, _ := e.store.GetUserGroups(ctx, userID)
	if err := e.store.SetUserGroups(ctx, userID, append(groups, groupID)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *testEnv) do(method, path, token string, body any) (int, string) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.http.URL+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (e *testEnv) expect(method, path, token string, body any, want int) string {
	e.t.Helper()
	got, out := e.do(method, path, token, body)
	if got != want {
		e.t.Fatalf("%s %s = %d, want %d (body: %.200s)", method, path, got, want, out)
	}
	return out
}

// waitAudit polls for an audit entry; Record runs in a goroutine. key is
// "<action>" or "<action>.<outcome>" (deployment.restart.success); contains
// must appear in the resource name, the reason or the details (as JSON).
func (e *testEnv) waitAudit(key, contains string) models.AuditLog {
	e.t.Helper()
	action, outcome := audit.SplitLegacyAction(key)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := e.store.ListAuditLogsFiltered(context.Background(), 100, 0,
			store.AuditFilter{Action: action, ActionExact: true, Outcome: outcome})
		for _, l := range logs {
			if strings.Contains(auditText(l), contains) {
				return l
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	logs, _ := e.store.ListAuditLogsFiltered(context.Background(), 20, 0, store.AuditFilter{})
	e.t.Fatalf("audit %q (%q) not recorded; latest: %+v", key, contains, logs)
	return models.AuditLog{}
}

func auditText(l models.AuditLog) string {
	d, _ := json.Marshal(l.Details)
	return l.ResourceName + " " + l.Reason + " " + string(d)
}

func (e *testEnv) noAudit(key string) {
	e.t.Helper()
	time.Sleep(150 * time.Millisecond)
	action, outcome := audit.SplitLegacyAction(key)
	logs, _ := e.store.ListAuditLogsFiltered(context.Background(), 100, 0,
		store.AuditFilter{Action: action, ActionExact: true, Outcome: outcome})
	if len(logs) > 0 {
		e.t.Fatalf("unexpected audit %q: %+v", key, logs[0])
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

func TestAuthRequired(t *testing.T) {
	e := newTestEnv(t)
	for _, p := range []string{"/api/namespaces", "/api/namespaces/team-a/pods", "/api/admin/users", "/api/admin/recordings"} {
		e.expect("GET", p, "", nil, http.StatusUnauthorized)
		e.expect("GET", p, "not-a-jwt", nil, http.StatusUnauthorized)
	}
	// A token signed with another key is rejected.
	forged, _ := auth.GenerateToken([]byte("some-other-signing-key-32-bytes!"), 1, "admin", "x", time.Hour)
	e.expect("GET", "/api/namespaces", forged, nil, http.StatusUnauthorized)
}

func TestRevokedSessionIsRejected(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusOK)

	e.expect("POST", "/api/admin/users/"+itoa(int64(bobID))+"/revoke-sessions", admin, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusUnauthorized)
}

func TestDeactivatedUserIsRejected(t *testing.T) {
	e := newTestEnv(t)
	id, tok := e.user("carol", false)
	e.grant(id, [4]any{0, "team-a", "pods", "list"})
	e.expect("GET", "/api/namespaces/team-a/pods", tok, nil, http.StatusOK)
	_ = e.store.UpdateUser(context.Background(), models.User{ID: id, Username: "carol", IsActive: false})
	e.expect("GET", "/api/namespaces/team-a/pods", tok, nil, http.StatusUnauthorized)
}

func TestLoginLockout(t *testing.T) {
	e := newTestEnv(t)
	hash, _ := auth.HashPassword("Correct-horse-1")
	if _, err := e.store.CreateUser(context.Background(), "dave", hash); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		e.expect("POST", "/api/auth/login", "", map[string]string{"username": "dave", "password": "wrong"}, http.StatusUnauthorized)
	}
	// Locked even with the right password.
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "dave", "password": "Correct-horse-1"}, http.StatusTooManyRequests)
	e.waitAudit("user.login.locked", "")
}

// ─── Admin-only surface ─────────────────────────────────────────────────────

func TestAdminEndpointsRequireAdmin(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	// Even a user with every namespace permission is not an admin.
	e.grant(bobID, [4]any{0, "team-a", "pods", "exec"}, [4]any{0, "team-a", "secrets", "reveal"})

	adminGets := []string{
		"/api/admin/users", "/api/admin/groups", "/api/admin/roles", "/api/admin/ldap",
		"/api/admin/azure-ad", "/api/admin/clusters", "/api/admin/audit-logs",
		"/api/admin/sessions", "/api/admin/recordings", "/api/admin/recordings/settings", "/api/admin/overview",
		"/api/admin/nodes",
	}
	for _, p := range adminGets {
		e.expect("GET", p, bob, nil, http.StatusForbidden)
		e.expect("GET", p, admin, nil, http.StatusOK)
	}
	e.expect("POST", "/api/admin/users", bob, map[string]string{"username": "eve", "password": "Passw0rd!x"}, http.StatusForbidden)
	e.expect("DELETE", "/api/admin/clusters/1", bob, nil, http.StatusForbidden)
}

func TestNodesAdminOnly(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	// A namespace permission is no node permission: nodes are for admins.
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "pods", "get"})
	_, _ = e.client.CoreV1().Nodes().Create(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}, metav1.CreateOptions{})

	e.expect("GET", "/api/admin/nodes", bob, nil, http.StatusForbidden)
	e.waitAudit("node.list.denied", "admin_only")
	e.expect("GET", "/api/admin/nodes/n1", bob, nil, http.StatusForbidden)
	e.waitAudit("node.get.denied", "n1")
	e.expect("GET", "/api/admin/nodes/n1/metrics/history?range=1h", bob, nil, http.StatusForbidden)
	e.expect("GET", "/api/admin/nodes", "", nil, http.StatusUnauthorized)

	e.expect("GET", "/api/admin/nodes/n1", admin, nil, http.StatusOK)
	e.expect("GET", "/api/admin/nodes/missing", admin, nil, http.StatusNotFound)
	e.waitAudit("node.get.failed", "not_found")
}

func TestAdminMustChangePasswordIsBlocked(t *testing.T) {
	e := newTestEnv(t)
	id, tok := e.user("fresh-admin", true)
	_ = e.store.UpdateUser(context.Background(), models.User{ID: id, Username: "fresh-admin", IsActive: true, IsAdmin: true, MustChangePassword: true})
	e.expect("GET", "/api/admin/users", tok, nil, http.StatusForbidden)
}

func TestRecordingWritesAuditDenials(t *testing.T) {
	e := newTestEnv(t)
	_, bob := e.user("bob", false)
	e.expect("DELETE", "/api/admin/recordings/7", bob, nil, http.StatusForbidden)
	e.waitAudit("recording.delete.denied", `"id":7`)
	e.expect("PUT", "/api/admin/recordings/settings", bob, models.RecordingSettings{Enabled: false, MaxSessionMB: 1, MaxTotalMB: 1}, http.StatusForbidden)
	e.waitAudit("settings.update.denied", "")
}

// ─── Namespace permissions ──────────────────────────────────────────────────

func TestNamespaceListOnlyShowsGranted(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})

	out := e.expect("GET", "/api/namespaces", bob, nil, http.StatusOK)
	if !strings.Contains(out, "team-a") || strings.Contains(out, "team-b") || strings.Contains(out, "team-c") {
		t.Fatalf("namespace leak: %s", out)
	}
	out = e.expect("GET", "/api/namespaces", admin, nil, http.StatusOK)
	for _, ns := range []string{"team-a", "team-b", "team-c"} {
		if !strings.Contains(out, ns) {
			t.Fatalf("admin should see %s: %s", ns, out)
		}
	}
}

func TestResourceAccessFollowsGrants(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})

	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-b/pods", bob, nil, http.StatusForbidden)        // other namespace
	e.expect("GET", "/api/namespaces/team-a/deployments", bob, nil, http.StatusForbidden) // other resource
	e.expect("GET", "/api/namespaces/team-a/pods/api-1", bob, nil, http.StatusForbidden)  // list ≠ get
	e.expect("GET", "/api/namespaces/team-a/secrets", bob, nil, http.StatusForbidden)

	out := e.expect("GET", "/api/namespaces/team-a/permissions", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"pods"`) || strings.Contains(out, "secrets") {
		t.Fatalf("permissions = %s", out)
	}
	e.expect("GET", "/api/namespaces/team-b/permissions", bob, nil, http.StatusForbidden)
}

func TestClusterScopedGrant(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{2, "team-a", "pods", "list"}) // beta only; alpha is active
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusForbidden)

	carolID, carol := e.user("carol", false)
	e.grant(carolID, [4]any{1, "team-a", "pods", "list"}) // alpha
	e.expect("GET", "/api/namespaces/team-a/pods", carol, nil, http.StatusOK)
}

func TestWriteActionsDeniedAndAudited(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "deployments", "list"}, [4]any{0, "team-a", "deployments", "get"})

	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", bob, nil, http.StatusForbidden)
	e.waitAudit("deployment.restart.denied", "api")
	e.expect("POST", "/api/namespaces/team-a/deployments/api/scale", bob, map[string]int{"replicas": 3}, http.StatusForbidden)
	e.waitAudit("deployment.scale.denied", "api")
	e.expect("POST", "/api/namespaces/team-a/deployments/api/apply", bob, map[string]any{"yaml": "x", "dryRun": true}, http.StatusForbidden)
	e.waitAudit("deployment.apply.denied", "api")

	// Granting restart lets it through.
	e.grant(bobID, [4]any{0, "team-a", "deployments", "restart"})
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", bob, nil, http.StatusOK)
	e.waitAudit("deployment.restart.success", "api")
}

func TestExecRequiresPermission(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "pods", "get"})
	e.expect("GET", "/ws/namespaces/team-a/pods/api-1/exec", bob, nil, http.StatusForbidden)
	e.waitAudit("pod.exec.denied", "api-1")
}

// WebSocket URLs carry a single-use ticket bound to the path, never the JWT.
func TestWSTicket(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/ws-ticket", "", map[string]string{"path": "/ws/events"}, http.StatusUnauthorized)
	e.expect("POST", "/api/ws-ticket", admin, map[string]string{"path": "/api/admin/users"}, http.StatusBadRequest)

	path := "/ws/namespaces/team-a/pods/api-1/logs"
	var out struct{ Ticket string }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/ws-ticket", admin, map[string]string{"path": path}, http.StatusOK)), &out)
	e.expect("GET", "/ws/namespaces/team-a/pods/api-2/logs?ticket="+out.Ticket, "", nil, http.StatusUnauthorized)
	// The failed attempt above burned it.
	e.expect("GET", path+"?ticket="+out.Ticket, "", nil, http.StatusUnauthorized)
	e.expect("GET", path+"?token="+admin, "", nil, http.StatusUnauthorized)

	_ = json.Unmarshal([]byte(e.expect("POST", "/api/ws-ticket", admin, map[string]string{"path": path}, http.StatusOK)), &out)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+path+"?container=app&ticket="+out.Ticket, nil)
	if err != nil {
		t.Fatalf("dial with ticket: %v", err)
	}
	conn.Close()
	e.waitAudit("pod.logs.success", "api-1")
}

// The live events feed shows a non-admin only what they may list; an admin sees it all.
func TestEventsFeedFollowsGrants(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})

	listen := func(token string) *websocket.Conn {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+"/ws/events",
			http.Header{"Authorization": {"Bearer " + token}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	bobConn, adminConn := listen(bob), listen(admin)
	time.Sleep(100 * time.Millisecond) // both subscribed

	events := []kube.ResourceEvent{
		{Verb: "updated", Kind: "Pod", Namespace: "team-a", Name: "a-visible"},
		{Verb: "updated", Kind: "Pod", Namespace: "team-b", Name: "other-ns"},
		{Verb: "updated", Kind: "ConfigMap", Namespace: "team-a", Name: "no-configmap-grant"},
		{Verb: "event", Kind: "Event", Namespace: "team-a", Name: "e1", InvolvedKind: "Pod", InvolvedName: "b-visible", Type: "Warning"},
		{Verb: "event", Kind: "Event", Name: "e2", InvolvedKind: "Node", InvolvedName: "node-1"},
		{Verb: "added", Kind: "Namespace", Name: "team-a"},
		{Verb: "added", Kind: "Namespace", Name: "team-c"},
	}
	for _, ev := range events {
		e.alpha.EventBus().Publish(ev)
	}
	read := func(conn *websocket.Conn) []string {
		var names []string
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		for {
			var ev kube.ResourceEvent
			if err := conn.ReadJSON(&ev); err != nil {
				return names
			}
			if ev.Verb == "event" {
				names = append(names, ev.InvolvedName)
			} else {
				names = append(names, ev.Name)
			}
		}
	}
	if got := strings.Join(read(bobConn), ","); got != "a-visible,b-visible,team-a" {
		t.Fatalf("bob saw %s", got)
	}
	if got := read(adminConn); len(got) != len(events) {
		t.Fatalf("admin saw %v", got)
	}
}

// ─── Secrets ────────────────────────────────────────────────────────────────

func TestSecretMetadataNeverLeaksValues(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "secrets", "list"}, [4]any{0, "team-a", "secrets", "get"})

	encoded := base64.StdEncoding.EncodeToString([]byte(secretValue))
	for _, p := range []string{"/api/namespaces/team-a/secrets", "/api/namespaces/team-a/secrets/db"} {
		out := e.expect("GET", p, bob, nil, http.StatusOK)
		if strings.Contains(out, secretValue) || strings.Contains(out, encoded) {
			t.Fatalf("%s leaked the secret value: %s", p, out)
		}
		if strings.Contains(out, "last-applied-configuration") {
			t.Fatalf("%s returned the last-applied annotation: %s", p, out)
		}
		if !strings.Contains(out, `"name":"password"`) || !strings.Contains(out, `"size":18`) || !strings.Contains(out, `"owner":"payments"`) {
			t.Fatalf("%s missing key metadata: %s", p, out)
		}
	}
	e.expect("GET", "/api/namespaces/team-a/secrets/missing", bob, nil, http.StatusNotFound)
}

func TestSecretRevealRequiresRevealAction(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "secrets", "list"}, [4]any{0, "team-a", "secrets", "get"})

	out := e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{"key": "password"}, http.StatusForbidden)
	if strings.Contains(out, secretValue) {
		t.Fatal("denied reveal leaked the value")
	}
	e.waitAudit("secret.reveal.denied", `"key":"password"`)
	e.noAudit("secret.reveal.success")

	e.grant(bobID, [4]any{0, "team-a", "secrets", "reveal"})
	out = e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{"key": "password"}, http.StatusOK)
	if !strings.Contains(out, `"value":"`+secretValue+`"`) || !strings.Contains(out, `"encoding":"text"`) {
		t.Fatalf("reveal = %s", out)
	}
	e.waitAudit("secret.reveal.success", `"key":"password"`)

	// Binary values come back base64-encoded and flagged.
	out = e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{"key": "keystore"}, http.StatusOK)
	if !strings.Contains(out, `"encoding":"base64"`) || !strings.Contains(out, `"value":"//4AAQ=="`) {
		t.Fatalf("binary reveal = %s", out)
	}

	e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{"key": "nope"}, http.StatusNotFound)
	e.waitAudit("secret.reveal.failed", "key_not_found")
	e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{}, http.StatusBadRequest)

	// Reveal in team-a does not carry over to team-b.
	e.expect("POST", "/api/namespaces/team-b/secrets/db/reveal", bob, map[string]string{"key": "password"}, http.StatusForbidden)
}

func TestAdminCanRevealSecrets(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	out := e.expect("GET", "/api/namespaces/team-a/permissions", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"secrets":["list","get","reveal","edit"]`) {
		t.Fatalf("admin permissions = %s", out)
	}
	e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", admin, map[string]string{"key": "password"}, http.StatusOK)
	e.waitAudit("secret.reveal.success", `"key":"password"`)
}

func TestSecretYAMLAndApplyRequireEdit(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	// reveal is not enough: the YAML editor needs secrets:edit.
	e.grant(bobID, [4]any{0, "team-a", "secrets", "list"}, [4]any{0, "team-a", "secrets", "get"}, [4]any{0, "team-a", "secrets", "reveal"})

	out := e.expect("GET", "/api/namespaces/team-a/secrets/db/yaml", bob, nil, http.StatusForbidden)
	if strings.Contains(out, secretValue) {
		t.Fatal("denied YAML leaked the value")
	}
	e.waitAudit("secret.view_yaml.denied", "db")
	e.expect("POST", "/api/namespaces/team-a/secrets/db/apply", bob, map[string]any{"yaml": "x", "dryRun": true}, http.StatusForbidden)
	e.waitAudit("secret.apply.denied", "db")

	e.grant(bobID, [4]any{0, "team-a", "secrets", "edit"})
	out = e.expect("GET", "/api/namespaces/team-a/secrets/db/yaml", bob, nil, http.StatusOK)
	if !strings.Contains(out, "stringData") || !strings.Contains(out, "password: "+secretValue) {
		t.Fatalf("editable YAML should carry plain-text values: %s", out)
	}
	e.waitAudit("secret.view_yaml.success", "db")
	// Edit in team-a does not carry over to team-b.
	e.expect("GET", "/api/namespaces/team-b/secrets/db/yaml", bob, nil, http.StatusForbidden)
}

// With the read-only ClusterRole the API server refuses writes. That must
// reach the user as 403 with the reason, not a generic 502.
func TestKubernetesForbiddenOnWriteIsReported(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.client.PrependReactor("patch", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "api", nil)
	})
	out := e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusForbidden)
	if !strings.Contains(out, "forbidden") {
		t.Fatalf("restart error should carry the API server reason: %s", out)
	}
	e.waitAudit("deployment.restart.failed", "api")
}

// closeAfterPendingWrites closes the DB only after any in-flight write has
// finished. Audit entries are written from goroutines, and sql.DB.Close does
// not wait for a running statement: that write could create a SQLite journal
// file while t.TempDir is being removed ("directory not empty"). The pool has
// one connection, so acquiring it waits for the in-flight write; closing the
// DB while holding it stops any later one.
func closeAfterPendingWrites(db *sql.DB) {
	conn, err := db.Conn(context.Background())
	_ = db.Close()
	if err == nil {
		_ = conn.Close()
	}
}

// resetGlobalLimiters clears the process-wide login lockout and write-action
// rate limits. Every test env starts a fresh DB whose user ids repeat (1, 2…),
// so state left by an earlier test — or an earlier -count iteration — would
// otherwise lock out or rate-limit unrelated tests.
func resetGlobalLimiters() {
	deployActionsLimitersMu.Lock()
	deployActionsLimiters = map[int]*rate.Limiter{}
	deployActionsLimitersMu.Unlock()
	g := LoginGate()
	g.mu.Lock()
	g.byIPUser = map[string]*loginAttempt{}
	g.mu.Unlock()
}
