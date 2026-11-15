package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// A disabled account, or a non-admin who must still change the password,
// can't keep using a session for the actions behind s.can: one-command exec,
// shell / log sockets, the ws ticket, secret reveal, apply, restart.
func TestSessionActionsRefusedForInactiveOrMustChange(t *testing.T) {
	e := newTestEnv(t)
	fakeCommands(t)
	e.runningPod()
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "exec"}, [4]any{0, "team-a", "pods", "logs"},
		[4]any{0, "team-a", "secrets", "reveal"}, [4]any{0, "team-a", "secrets", "edit"},
		[4]any{0, "team-a", "deployments", "restart"}, [4]any{0, "team-a", "deployments", "edit"})
	cmd := map[string]any{"command": []string{"cat", "/etc/os-release"}}
	e.expect("POST", "/api/namespaces/team-a/pods/app-1/exec", bob, cmd, http.StatusOK)

	set := func(active, mustChange bool) {
		_ = e.store.UpdateUser(context.Background(), models.User{ID: bobID, Username: "bob", IsActive: active, MustChangePassword: mustChange})
	}
	set(true, true)
	e.expect("POST", "/api/namespaces/team-a/pods/app-1/exec", bob, cmd, http.StatusForbidden)
	e.waitAudit("pod.exec.denied", "app-1")
	e.expect("GET", "/ws/namespaces/team-a/pods/app-1/exec", bob, nil, http.StatusForbidden)
	e.expect("POST", "/api/ws-ticket", bob, map[string]string{"path": "/ws/namespaces/team-a/pods/app-1/exec"}, http.StatusForbidden)
	if out := e.expect("POST", "/api/namespaces/team-a/secrets/db/reveal", bob, map[string]string{"key": "password"}, http.StatusForbidden); strings.Contains(out, "s3cr3t") {
		t.Fatal("reveal leaked the value")
	}
	e.waitAudit("secret.reveal.denied", `"key":"password"`)
	e.expect("POST", "/api/namespaces/team-a/deployments/api/apply", bob, map[string]any{"yaml": "x", "dryRun": true}, http.StatusForbidden)
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", bob, nil, http.StatusForbidden)

	// Disabled behind the admin's back (a ticket or key path would still
	// carry the user id): every s.can action is refused too.
	set(false, false)
	e.expect("POST", "/api/namespaces/team-a/pods/app-1/exec", bob, cmd, http.StatusForbidden)
	e.expect("POST", "/api/ws-ticket", bob, map[string]string{"path": "/ws/namespaces/team-a/pods/app-1/exec"}, http.StatusUnauthorized)
	if (&Server{store: e.store}).can(context.Background(), bobID, "team-a", "pods", "exec") {
		t.Fatal("can() allows a disabled user")
	}
}

// Disabling an account in Admin → Users ends its sessions at once.
func TestDisablingUserRevokesSessions(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	path := "/api/admin/users/" + itoa(int64(bobID))
	e.expect("PUT", path, admin, map[string]any{"username": "bob", "isActive": false}, http.StatusOK)
	e.expect("PUT", path, admin, map[string]any{"username": "bob", "isActive": true}, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods", bob, nil, http.StatusUnauthorized)

	// A body without the name doesn't blank it.
	e.expect("PUT", path, admin, map[string]any{"isActive": true}, http.StatusBadRequest)
	if u, _ := e.store.GetUserByID(context.Background(), bobID); u.Username != "bob" {
		t.Fatalf("username = %q", u.Username)
	}
}

func TestKubeconfigThatRunsOrReadsIsRefused(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	kc := func(user string) map[string]any {
		raw := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://127.0.0.1:1"}
users:
- name: u
  user:
` + user + `
contexts:
- name: x
  context: {cluster: c, user: u}
current-context: x
`
		return map[string]any{"name": "evil", "method": "kubeconfig", "kubeconfigBase64": base64.StdEncoding.EncodeToString([]byte(raw))}
	}
	for name, user := range map[string]string{
		"exec":          "    exec: {apiVersion: client.authentication.k8s.io/v1, command: sh, args: [-c, id]}",
		"auth-provider": "    auth-provider: {name: oidc}",
		"tokenFile":     "    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token",
		"client-key":    "    client-certificate: /data/app.db\n    client-key: /data/app.db",
	} {
		out := e.expect("POST", "/api/admin/clusters", admin, kc(user), http.StatusBadRequest)
		if !strings.Contains(out, "kubeconfig_unsupported") {
			t.Fatalf("%s: %s", name, out)
		}
	}
	// Inline credentials get past the check (and fail only on the unreachable server).
	out := e.expect("POST", "/api/admin/clusters", admin, kc("    token: abc"), http.StatusBadRequest)
	if strings.Contains(out, "kubeconfig_unsupported") {
		t.Fatalf("inline token refused: %s", out)
	}
}

func TestCSVCellsCantBeFormulas(t *testing.T) {
	for in, want := range map[string]string{
		`=HYPERLINK("http://x","y")`: `'=HYPERLINK("http://x","y")`,
		"+1":                         "'+1", "-1": "'-1", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		"alice": "alice", "": "", "a=b": "a=b",
	} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
	// End to end: a failed sign-in typed as a formula lands quoted in the audit CSV.
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": `=HYPERLINK("http://x")`, "password": "x"}, http.StatusUnauthorized)
	e.waitAudit("user.login.failed", "HYPERLINK")
	if out := e.expect("GET", "/api/admin/audit-logs/export", admin, nil, http.StatusOK); !strings.Contains(out, `'=HYPERLINK`) {
		t.Fatalf("audit CSV: %.300s", out)
	}
}

func TestRequestBodyLimits(t *testing.T) {
	e := newTestEnv(t)
	big := strings.Repeat("a", 2<<20)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "x", "password": big}, http.StatusRequestEntityTooLarge)
	// A user name over 256 characters is refused before it reaches the audit.
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": strings.Repeat("u", 300), "password": "x"}, http.StatusBadRequest)
	e.noAudit("user.login.failed")
}

func TestClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	t.Cleanup(func() { _ = SetTrustedProxies("") })
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	_ = SetTrustedProxies("")
	if got := clientIP(req("203.0.113.9:1234", "10.20.0.7")); got != "203.0.113.9" {
		t.Fatalf("no trusted proxies: %s", got)
	}
	if err := SetTrustedProxies("10.0.0.0/8, 192.168.1.5"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ remote, xff, want string }{
		{"10.1.2.3:80", "198.51.100.4", "198.51.100.4"},              // through the ingress
		{"10.1.2.3:80", "6.6.6.6, 198.51.100.4", "198.51.100.4"},     // client-written entry ignored
		{"10.1.2.3:80", "198.51.100.4, 192.168.1.5", "198.51.100.4"}, // two proxies
		{"203.0.113.9:80", "198.51.100.4", "203.0.113.9"},            // not from a proxy
		{"10.1.2.3:80", "", "10.1.2.3"},                              // proxy, no header
		{"10.1.2.3:80", "garbage", "10.1.2.3"},                       // unparsable
		{"[::ffff:10.1.2.3]:80", "198.51.100.4", "198.51.100.4"},     // IPv4-mapped
	} {
		if got := clientIP(req(c.remote, c.xff)); got != c.want {
			t.Errorf("remote %s xff %q = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if err := SetTrustedProxies("10.0.0.0/33"); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}

// Changing X-Forwarded-For on every try no longer gets around the lock: the
// per-user counter locks the account after loginUserFailsBeforeLock tries,
// and without a trusted proxy the header isn't even read.
func TestLoginLockNotBypassedBySpoofedXFF(t *testing.T) {
	e := newTestEnv(t)
	_, _ = e.user("dave", false)
	h := e.server.routes()
	login := func(xff string) int {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"dave","password":"wrong"}`))
		r.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// No trusted proxy: the header is ignored, the 6th try is locked.
	for i := 0; i < loginFailsBeforeLock; i++ {
		if code := login("10.20.0." + itoa(int64(i))); code != http.StatusUnauthorized {
			t.Fatalf("try %d = %d", i, code)
		}
	}
	if code := login("10.20.0.99"); code != http.StatusTooManyRequests {
		t.Fatalf("6th try with a new XFF = %d, want 429", code)
	}
	if a := e.waitAudit("user.login.failed", "dave"); a.SourceIP != "192.0.2.1" {
		t.Fatalf("audit source ip = %q, want the connection's", a.SourceIP)
	}

	// Behind a trusted proxy every address counts on its own, but the user
	// counter still locks.
	resetGlobalLimiters()
	t.Cleanup(func() { _ = SetTrustedProxies("") })
	_ = SetTrustedProxies("192.0.2.1")
	for i := 0; i < loginUserFailsBeforeLock; i++ {
		if code := login("10.30.0." + itoa(int64(i))); code != http.StatusUnauthorized {
			t.Fatalf("try %d = %d", i, code)
		}
	}
	if code := login("10.30.0.200"); code != http.StatusTooManyRequests {
		t.Fatalf("try past the user limit = %d, want 429", code)
	}
}

func TestLoginGateForgetsOldFailures(t *testing.T) {
	g := &loginGate{attempts: map[string]*loginAttempt{}}
	keys := loginGateKeys("1.2.3.4", "x")
	g.recordFailure(keys)
	for _, a := range g.attempts {
		a.last = a.last.Add(-2 * loginLockWindow)
	}
	g.lastSweep = g.lastSweep.Add(-2 * time.Minute)
	g.recordFailure(loginGateKeys("5.6.7.8", "y"))
	if _, ok := g.attempts[keys[0].key]; ok || len(g.attempts) != 2 {
		t.Fatalf("stale counters kept: %v", g.attempts)
	}
}
