package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

// captureLog sends slog's default logger to a buffer for the test.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A WebSocket's request line says 101, not 200 (M29 #10).
func TestWebSocketLogsSwitchingProtocols(t *testing.T) {
	logs := captureLog(t)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err == nil {
			_ = c.Close()
		}
	})))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	for i := 0; i < 100 && !strings.Contains(logs(), "path=/ws/x"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs(), "status=101") {
		t.Fatalf("log: %s", logs())
	}
}

// Every metric family has # HELP and # TYPE, the status counter too.
func TestMetricsStatusCounterHasHelp(t *testing.T) {
	metricsRecordRequest(200, 1)
	rec := httptest.NewRecorder()
	handleMetrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	i := strings.Index(out, "# TYPE openconsole_http_requests_status_total counter")
	j := strings.Index(out, "openconsole_http_requests_status_total{")
	if i < 0 || j < i {
		t.Fatalf("metrics:\n%s", out)
	}
}

// A failed LDAP sign-in says why in the log: the audit entry only has
// bad_password, which doesn't tell an operator the directory is unreachable.
func TestLDAPSignInFailureIsLogged(t *testing.T) {
	e := newTestEnv(t)
	srv := ldapfake.Start(t, ldapfake.Directory())
	_, admin := e.user("root", true)
	setLDAP := func(url string) {
		e.expect("PUT", "/api/admin/ldap", admin, map[string]any{
			"enabled": true, "url": url, "timeoutSeconds": 2,
			"bindDn": ldapfake.ServiceDN, "bindPassword": ldapfake.ServicePwd,
			"userBaseDn": ldapfake.UsersDN, "userFilter": "(sAMAccountName=%s)", "usernameAttribute": "sAMAccountName",
		}, http.StatusOK)
	}
	id, _ := e.user("john", false)
	_ = e.store.SetUserAuthSource(context.Background(), id, models.AuthSourceLDAP)
	logs := captureLog(t)

	setLDAP(srv.URL())
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "john", "password": "Wrong-pass-1"}, http.StatusUnauthorized)
	if l := logs(); !strings.Contains(l, "level=INFO") || !strings.Contains(l, `msg="ldap sign-in failed" user=john`) {
		t.Fatalf("wrong password log: %s", l)
	}
	setLDAP("ldap://127.0.0.1:1")
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "john", "password": ldapfake.JohnPwd}, http.StatusUnauthorized)
	if l := logs(); !strings.Contains(l, `level=WARN msg="ldap sign-in failed" user=john`) || !strings.Contains(l, "127.0.0.1:1") {
		t.Fatalf("unreachable directory log: %s", l)
	}
	// First sign-in of a directory user (account created on sign-in): same line.
	e.expect("PUT", "/api/admin/ldap", admin, map[string]any{"enabled": true, "url": "ldap://127.0.0.1:1", "timeoutSeconds": 2,
		"bindDn": ldapfake.ServiceDN, "bindPassword": ldapfake.ServicePwd, "userBaseDn": ldapfake.UsersDN,
		"userFilter": "(sAMAccountName=%s)", "usernameAttribute": "sAMAccountName", "autoProvision": true}, http.StatusOK)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "newcomer", "password": "Any-pass-123"}, http.StatusUnauthorized)
	if l := logs(); !strings.Contains(l, `msg="ldap sign-in failed" user=newcomer`) {
		t.Fatalf("auto-provision log: %s", l)
	}
}
