package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/store"
)

// createKey creates an API key through the endpoint and returns its secret and id.
func (e *testEnv) createKey(session string, body map[string]any) (string, int) {
	e.t.Helper()
	var out struct {
		Secret string
		Key    struct{ ID int }
	}
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/me/api-keys", session, body, http.StatusCreated)), &out)
	return out.Secret, out.Key.ID
}

func keyBody(name string, namespaces []string, grants ...string) map[string]any {
	return map[string]any{"name": name, "clusters": []int{0}, "namespaces": namespaces, "grants": grants}
}

func (e *testEnv) doHeader(method, path, token string, header map[string]string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.http.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A safe read-only key reads pods, and nothing its scope leaves out; its
// calls are audited under the key's name; the secret is shown once.
func TestAPIKeyScopeAndAudit(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "pods", "get"}, [4]any{0, "team-a", "pods", "exec"},
		[4]any{0, "team-a", "secrets", "list"}, [4]any{0, "team-b", "pods", "list"})

	key, id := e.createKey(bob, keyBody("claude-dev", []string{"team-a"}, "pods:list", "pods:get"))
	if !regexp.MustCompile(`^oc_[0-9A-Za-z]{40}$`).MatchString(key) {
		t.Fatalf("secret %q", key)
	}
	e.waitAudit("api_key.create.success", "claude-dev")

	e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods/api-1", key, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/secrets", key, nil, http.StatusForbidden) // user has it, key does not
	e.expect("GET", "/api/namespaces/team-b/pods", key, nil, http.StatusForbidden)    // namespace outside the key
	e.expect("GET", "/ws/namespaces/team-a/pods/api-1/exec", key, nil, http.StatusForbidden)
	e.waitAudit("pod.exec.denied", "api-1")

	out := e.expect("GET", "/api/namespaces", key, nil, http.StatusOK)
	if !strings.Contains(out, "team-a") || strings.Contains(out, "team-b") {
		t.Fatalf("namespaces with key = %s", out)
	}
	out = e.expect("GET", "/api/namespaces/team-a/permissions", key, nil, http.StatusOK)
	if strings.Contains(out, "exec") || strings.Contains(out, "secrets") {
		t.Fatalf("permissions with key = %s", out)
	}
	out = e.expect("GET", "/api/auth/me", key, nil, http.StatusOK)
	if !strings.Contains(out, `"apiKey"`) || strings.Contains(out, key) || strings.Contains(out, "exec") {
		t.Fatalf("me with key = %s", out)
	}

	l := e.waitAudit("pod.list.success", "")
	if l.APIKeyID != id || l.APIKeyName != "claude-dev" || l.User != "bob" {
		t.Fatalf("audit entry = %+v", l)
	}
	_, admin := e.user("root", true)
	out = e.expect("GET", "/api/admin/audit-logs?source=api_key&apiKey=claude", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"apiKeyName":"claude-dev"`) || strings.Contains(out, `"action":"api_key.create"`) {
		t.Fatalf("audit filtered by key = %.300s", out)
	}
	// The list never carries the secret or its hash.
	out = e.expect("GET", "/api/me/api-keys", bob, nil, http.StatusOK)
	if strings.Contains(out, key) || strings.Contains(out, hashAPIKey(key)) || !strings.Contains(out, key[:9]) {
		t.Fatalf("list = %s", out)
	}
}

// The key's reach follows the owner's grants on every call.
func TestAPIKeyFollowsOwnerGrants(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, _ := e.createKey(bob, map[string]any{"name": "k", "clusters": []int{0}, "allNamespaces": true, "grants": []string{"pods:list"}})
	e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-b/pods", key, nil, http.StatusForbidden)

	// A namespace granted later is part of "all my namespaces".
	e.grant(bobID, [4]any{0, "team-b", "pods", "list"})
	e.expect("GET", "/api/namespaces/team-b/pods", key, nil, http.StatusOK)

	// Taking the grant away closes it for the key at once.
	if err := e.store.SetUserGroups(context.Background(), bobID, nil); err != nil {
		t.Fatal(err)
	}
	e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusForbidden)
	out := e.expect("GET", "/api/me/api-keys", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"invalidGrants":["pods:list"]`) {
		t.Fatalf("list should flag the lost grant: %s", out)
	}
}

// The server, not the UI, is the trust boundary for what a key may hold.
func TestAPIKeyCeilingIsEnforced(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{1, "team-a", "pods", "list"})

	e.expect("POST", "/api/me/api-keys", bob, keyBody("x", []string{"team-a"}, "pods:exec"), http.StatusBadRequest)
	e.waitAudit("api_key.create.denied", "pods:exec")
	e.expect("POST", "/api/me/api-keys", bob, keyBody("x", []string{"team-b"}, "pods:list"), http.StatusBadRequest)
	e.expect("POST", "/api/me/api-keys", bob, map[string]any{"name": "x", "clusters": []int{2}, "namespaces": []string{"team-a"}, "grants": []string{"pods:list"}}, http.StatusBadRequest)
	e.expect("POST", "/api/me/api-keys", bob, map[string]any{"name": "x", "clusters": []int{0}, "namespaces": []string{"team-a"}, "grants": []string{"pods:list"}, "adminScope": true}, http.StatusBadRequest)
	e.expect("POST", "/api/me/api-keys", bob, map[string]any{"name": "x", "clusters": []int{0}, "namespaces": []string{"team-a"}, "grants": []string{"pods:list"}, "expiresAt": time.Now().Add(-time.Hour)}, http.StatusBadRequest)
	_, id := e.createKey(bob, keyBody("x", []string{"team-a"}, "pods:list"))
	e.expect("POST", "/api/me/api-keys", bob, keyBody("x", []string{"team-a"}, "pods:list"), http.StatusBadRequest) // name taken
	e.expect("PUT", "/api/me/api-keys/"+itoa(int64(id)), bob, keyBody("x", []string{"team-a"}, "pods:list", "secrets:reveal"), http.StatusBadRequest)

	out := e.expect("GET", "/api/me/api-keys/ceiling", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"namespace":"team-a","grants":["pods:list"]`) || strings.Contains(out, "beta") {
		t.Fatalf("ceiling = %s", out)
	}

	// Another user's key is not found, not forbidden.
	_, carol := e.user("carol", false)
	e.expect("POST", "/api/me/api-keys/"+itoa(int64(id))+"/revoke", carol, nil, http.StatusNotFound)
}

// What a key can never do, whatever its scope.
func TestAPIKeyForbiddenEndpoints(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, id := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:list"))
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/me/api-keys"},
		{"GET", "/api/me/api-keys/ceiling"},
		{"POST", "/api/me/api-keys"},
		{"PUT", "/api/me/api-keys/" + itoa(int64(id))},
		{"POST", "/api/me/api-keys/" + itoa(int64(id)) + "/regenerate"},
		{"POST", "/api/me/api-keys/" + itoa(int64(id)) + "/revoke"},
		{"DELETE", "/api/me/api-keys/" + itoa(int64(id))},
		{"POST", "/api/auth/change-password"},
		{"POST", "/api/cluster/select"},
		{"POST", "/api/views"},
		{"PUT", "/api/views/1"},
		{"DELETE", "/api/views/1"},
	} {
		e.expect(c.method, c.path, key, map[string]any{}, http.StatusForbidden)
	}
	e.waitAudit("api_key.revoke.denied", "api_key_not_allowed")
	e.waitAudit("user.change_password.denied", "api_key_not_allowed")
	e.waitAudit("cluster.select.denied", "api_key_not_allowed")
	e.waitAudit("saved_view.create.denied", "api_key_not_allowed")
	e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusOK) // still alive
}

// Every /api/admin endpoint refuses a key without the admin scope, even an
// admin's; with the scope it works until the owner stops being an admin.
func TestAPIKeyAdminScope(t *testing.T) {
	e := newTestEnv(t)
	rootID, root := e.user("root", true)
	plain, _ := e.createKey(root, keyBody("plain", []string{"team-a"}, "pods:list"))
	scoped, _ := e.createKey(root, map[string]any{"name": "scoped", "clusters": []int{0}, "allNamespaces": true, "grants": []string{"pods:list"}, "adminScope": true})

	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := regexp.MustCompile(`r\.(Get|Post|Put|Delete)\("(/api/admin/[^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(routes) < 60 {
		t.Fatalf("found only %d admin routes", len(routes))
	}
	for _, m := range routes {
		path := strings.NewReplacer("{id}", "1", "{name}", "n1").Replace(m[2])
		e.server.keyLimits.mu.Lock()
		e.server.keyLimits.limiters = nil // this test calls more often than a key may
		e.server.keyLimits.mu.Unlock()
		if code, out := e.do(strings.ToUpper(m[1]), path, plain, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s with a key without the admin scope = %d (%.100s)", m[1], path, code, out)
		}
	}
	e.waitAudit("node.list.denied", "admin_only")

	for _, p := range []string{"/api/admin/users", "/api/admin/audit-logs", "/api/admin/nodes", "/api/admin/recordings"} {
		e.expect("GET", p, scoped, nil, http.StatusOK)
	}
	// The admin key still follows its own scope on namespaced resources.
	e.expect("GET", "/api/namespaces/team-a/pods", plain, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/deployments", plain, nil, http.StatusForbidden)
	e.expect("GET", "/api/namespaces/team-b/pods", plain, nil, http.StatusForbidden)

	// No longer an admin: the admin scope is worth nothing, and so are grants the user never had.
	_ = e.store.UpdateUser(context.Background(), models.User{ID: rootID, Username: "root", IsActive: true})
	e.expect("GET", "/api/admin/users", scoped, nil, http.StatusForbidden)
	e.expect("GET", "/api/namespaces/team-a/pods", scoped, nil, http.StatusForbidden)
}

// 401 means the key is not valid; anything else is 403.
func TestAPIKeyRejections(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	body := keyBody("revoked", []string{"team-a"}, "pods:list")
	revoked, id := e.createKey(bob, body)
	e.expect("POST", "/api/me/api-keys/"+itoa(int64(id))+"/revoke", bob, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods", revoked, nil, http.StatusUnauthorized)
	e.waitAudit("api_key.use.denied", "revoked")

	// Regenerate: new secret works, the old one does not; it comes back to life.
	var regen struct{ Secret string }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/me/api-keys/"+itoa(int64(id))+"/regenerate", bob, map[string]any{"expiresAt": time.Now().Add(time.Hour)}, http.StatusOK)), &regen)
	e.expect("GET", "/api/namespaces/team-a/pods", regen.Secret, nil, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods", revoked, nil, http.StatusUnauthorized)
	e.waitAudit("api_key.regenerate.success", "revoked")

	body["name"] = "expired"
	expired, expiredID := e.createKey(bob, body)
	past := time.Now().Add(-time.Minute)
	if err := e.store.RegenerateAPIKey(context.Background(), expiredID, expired[:9], hashAPIKey(expired), &past); err != nil {
		t.Fatal(err)
	}
	e.expect("GET", "/api/namespaces/team-a/pods", expired, nil, http.StatusUnauthorized)
	e.waitAudit("api_key.use.denied", "expired")

	e.expect("GET", "/api/namespaces/team-a/pods", "oc_unknownunknownunknownunknownunknownunkn", nil, http.StatusUnauthorized)

	body["name"] = "owner"
	owner, _ := e.createKey(bob, body)
	_ = e.store.UpdateUser(context.Background(), models.User{ID: bobID, Username: "bob", IsActive: true, MustChangePassword: true})
	e.expect("GET", "/api/namespaces/team-a/pods", owner, nil, http.StatusForbidden)
	e.waitAudit("api_key.use.denied", "must_change_password")
	_ = e.store.UpdateUser(context.Background(), models.User{ID: bobID, Username: "bob", IsActive: false})
	e.expect("GET", "/api/namespaces/team-a/pods", owner, nil, http.StatusUnauthorized)
	e.waitAudit("api_key.use.denied", "owner_inactive")

	// Deleting a key ends it too.
	_ = e.store.UpdateUser(context.Background(), models.User{ID: bobID, Username: "bob", IsActive: true})
	bob = e.token(bobID, "bob")
	e.expect("DELETE", "/api/me/api-keys/"+itoa(int64(id)), bob, nil, http.StatusNoContent)
	e.expect("GET", "/api/namespaces/team-a/pods", regen.Secret, nil, http.StatusUnauthorized)
}

// A storage error refuses the key (sessions fail open, keys fail closed).
func TestAPIKeyLookupErrorRefuses(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	database.Conn.Close()
	s := &Server{store: st}
	if _, status, _ := s.AuthenticateKey(httptest.NewRequest("GET", "/api/namespaces", nil), "oc_x", 0); status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
}

// A key's reads are audited even with the auto-refresh header.
func TestAPIKeyIgnoresRefreshHeader(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, _ := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:list"))
	if code, _ := e.doHeader("GET", "/api/namespaces/team-a/pods", key, map[string]string{refreshHeader: "auto"}); code != http.StatusOK {
		t.Fatal(code)
	}
	if l := e.waitAudit("pod.list.success", ""); l.APIKeyName != "k" {
		t.Fatalf("entry = %+v", l)
	}
}

// The cluster comes from X-OpenConsole-Cluster per request, inside the key's clusters.
func TestAPIKeyClusterHeader(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	anyKey, _ := e.createKey(bob, keyBody("any", []string{"team-a"}, "pods:list"))
	alphaOnly, _ := e.createKey(bob, map[string]any{"name": "alpha", "clusters": []int{e.alphaID}, "namespaces": []string{"team-a"}, "grants": []string{"pods:list"}})

	if code, out := e.doHeader("GET", "/api/namespaces/team-a/pods", anyKey, map[string]string{clusterHeader: "beta"}); code != http.StatusOK || !strings.Contains(out, "beta-pod") {
		t.Fatalf("beta by name = %d %s", code, out)
	}
	if code, out := e.doHeader("GET", "/api/namespaces/team-a/pods", anyKey, map[string]string{clusterHeader: "2"}); code != http.StatusOK || !strings.Contains(out, "beta-pod") {
		t.Fatalf("beta by id = %d %s", code, out)
	}
	if code, out := e.doHeader("GET", "/api/namespaces/team-a/pods", anyKey, nil); code != http.StatusOK || !strings.Contains(out, "api-1") {
		t.Fatalf("default cluster = %d %s", code, out)
	}
	if code, _ := e.doHeader("GET", "/api/namespaces/team-a/pods", anyKey, map[string]string{clusterHeader: "nope"}); code != http.StatusBadRequest {
		t.Fatalf("unknown cluster = %d", code)
	}
	if code, _ := e.doHeader("GET", "/api/namespaces/team-a/pods", alphaOnly, map[string]string{clusterHeader: "beta"}); code != http.StatusForbidden {
		t.Fatalf("cluster outside the key = %d", code)
	}
	e.waitAudit("api_key.use.denied", "forbidden")
}

// ws-ticket with a key: the ticket carries the key, the log socket works and is audited under it.
func TestAPIKeyWebSocketTicket(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "logs"})
	key, _ := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:logs"))
	path := "/ws/namespaces/team-a/pods/api-1/logs"
	var out struct{ Ticket string }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/ws-ticket", key, map[string]string{"path": path}, http.StatusOK)), &out)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+path+"?container=app&ticket="+out.Ticket, nil)
	if err != nil {
		t.Fatalf("dial with ticket: %v", err)
	}
	conn.Close()
	if l := e.waitAudit("pod.logs.success", "api-1"); l.APIKeyName != "k" {
		t.Fatalf("entry = %+v", l)
	}
}

func TestAPIKeyRateLimit(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, _ := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:list"))
	limited := 0
	for i := 0; i < apiKeyBurst+10; i++ {
		if code, _ := e.do("GET", "/api/features", key, nil); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("never rate limited")
	}
	e.waitAudit("api_key.use.rate_limited", "")
}

func TestAPIKeysFeatureFlag(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, _ := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:list"))
	SetDisabledFeatures([]string{FeatureAPIKeys})
	t.Cleanup(func() { SetDisabledFeatures(nil) })
	e = &testEnv{t: t, store: e.store, server: e.server, http: httptest.NewServer(e.server.Router())}
	t.Cleanup(e.http.Close)
	e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusUnauthorized)
	e.expect("GET", "/api/me/api-keys", bob, nil, http.StatusForbidden)
}

// A shell opened with a key is never left unrecorded: no recorder, no shell.
func TestAPIKeyShellMustBeRecorded(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-a", "pods", "exec"})
	key, _ := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:exec"))
	// The fake clientset has no REST config; a real (unreachable) one gets the handler to the recording step.
	m := kube.NewManager()
	if err := m.ApplyCredentials(models.KubeCredentials{Method: "token", Server: "https://127.0.0.1:1", Token: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	e.server.clusters.Put(e.alphaID, m)
	e.server.recorder = nil
	upgrade := map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
	if code, out := e.doHeader("GET", "/ws/namespaces/team-a/pods/api-1/exec", key, upgrade); code != http.StatusServiceUnavailable {
		t.Fatalf("key shell without a recording = %d %s", code, out)
	}
	e.waitAudit("pod.exec.failed", "recording_unavailable")
}

// A refused key answers every time but is audited once a minute per reason.
func TestAPIKeyRefusalAuditThrottled(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	key, id := e.createKey(bob, keyBody("k", []string{"team-a"}, "pods:list"))
	e.expect("POST", "/api/me/api-keys/"+itoa(int64(id))+"/revoke", bob, nil, http.StatusOK)
	for i := 0; i < 5; i++ {
		e.expect("GET", "/api/namespaces/team-a/pods", key, nil, http.StatusUnauthorized)
	}
	e.waitAudit("api_key.use.denied", "revoked")
	time.Sleep(150 * time.Millisecond)
	if n, _ := e.store.CountAuditLogsFiltered(context.Background(), store.AuditFilter{Action: "api_key.use", ActionExact: true}); n != 1 {
		t.Fatalf("%d audit rows for 5 refused requests", n)
	}
}

// With a key: allowed when the policy lets keys exec, 403 api_access_policy when it doesn't,
// and never unrecorded.
func TestAPIKeyExecCommand(t *testing.T) {
	e := newTestEnv(t)
	fakeCommands(t)
	e.runningPod()
	bobID, bob := e.user("bob", false)
	role := e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-a", "pods", "exec"})
	key, _ := e.createKey(bob, keyBody("agent", []string{"team-a"}, "pods:exec"))
	body := map[string]any{"command": []string{"cat", "/etc/os-release"}}

	e.expect("POST", execPath, key, body, http.StatusOK)
	recs, _, _ := e.server.recorder.List(context.Background(), models.RecordingFilter{APIKey: "agent"})
	if len(recs) != 1 || recs[0].Mode != models.RecordingModeCommand {
		t.Fatalf("key command recordings = %+v", recs)
	}

	_ = e.store.SetRoleAPIAccess(context.Background(), role, rbac.AccessSafeRead)
	if out := e.expect("POST", execPath, key, body, http.StatusForbidden); !strings.Contains(out, reasonAPIAccessPolicy) {
		t.Fatal(out)
	}
	e.waitAudit("pod.exec.denied", reasonAPIAccessPolicy)

	_ = e.store.SetRoleAPIAccess(context.Background(), role, rbac.AccessFull)
	e.server.recorder = nil
	e.expect("POST", execPath, key, body, http.StatusServiceUnavailable)
	e.waitAudit("pod.exec.failed", "recording_unavailable")
	// A web session runs it unrecorded when recording can't start (as a shell does).
	e.expect("POST", execPath, bob, body, http.StatusOK)
}

// The REST log follows the key's scope like every read, and is audited with the key's name.
func TestAPIKeyRESTLogs(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "logs"}, [4]any{0, "team-b", "pods", "logs"})
	key, _ := e.createKey(bob, keyBody("reader", []string{"team-a"}, "pods:logs"))
	if out := e.expect("GET", "/api/namespaces/team-a/pods/api-1/logs", key, nil, http.StatusOK); out != "fake logs" {
		t.Fatalf("log = %q", out)
	}
	if l := e.waitAudit("pod.logs.success", "api-1"); l.APIKeyName != "reader" {
		t.Fatalf("audit key = %q", l.APIKeyName)
	}
	e.expect("GET", "/api/namespaces/team-b/pods/api-1/logs", key, nil, http.StatusForbidden)
}
