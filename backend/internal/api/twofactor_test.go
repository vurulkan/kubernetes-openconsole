package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

func (e *testEnv) localUser(name, password string, admin bool) int {
	e.t.Helper()
	hash, _ := auth.HashPassword(password)
	id, err := e.store.CreateUser(context.Background(), name, hash)
	if err != nil {
		e.t.Fatal(err)
	}
	if admin {
		u, _ := e.store.GetUserByID(context.Background(), id)
		u.IsAdmin = true
		if err := e.store.UpdateUser(context.Background(), *u); err != nil {
			e.t.Fatal(err)
		}
	}
	return id
}

func (e *testEnv) setPolicy(admin, policy string) {
	e.t.Helper()
	e.expect("PUT", "/api/admin/session", admin, map[string]any{"twoFactorPolicy": policy}, http.StatusOK)
}

type loginAnswer struct {
	Token             string `json:"token"`
	TwoFactor         string `json:"twoFactor"`
	Challenge         string `json:"challenge"`
	RecoveryCodesLeft *int   `json:"recoveryCodesLeft"`
}

func (e *testEnv) login(name, password string) loginAnswer {
	e.t.Helper()
	var a loginAnswer
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/auth/login", "", map[string]string{"username": name, "password": password}, http.StatusOK)), &a)
	return a
}

// enable sets two-factor sign-in up for the session's user; returns the secret and the recovery codes.
func (e *testEnv) enable(token string) (string, []string, string) {
	e.t.Helper()
	var setup struct{ Secret, URI, QR string }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/me/2fa/setup", token, nil, http.StatusOK)), &setup)
	if !strings.HasPrefix(setup.QR, "data:image/png;base64,") || !strings.Contains(setup.URI, "secret="+setup.Secret) {
		e.t.Fatalf("setup = %+v", setup)
	}
	var done struct {
		RecoveryCodes []string
		Token         string
	}
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/me/2fa/confirm", token, map[string]string{"code": auth.TOTPCode(setup.Secret, time.Now())}, http.StatusOK)), &done)
	if len(done.RecoveryCodes) != 10 || done.Token == "" {
		e.t.Fatalf("confirm = %+v", done)
	}
	return setup.Secret, done.RecoveryCodes, done.Token
}

// freshStep forgets the last code used, so the current one works again.
func (e *testEnv) freshStep(userID int) {
	if _, err := e.db.Conn.Exec(`UPDATE users SET totp_last_step = 0 WHERE id = ?`, userID); err != nil {
		e.t.Fatal(err)
	}
}

func TestTwoFactorSignIn(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	id := e.localUser("tina", "Tina-passw0rd", false)

	// Off (the default): sign-in as before, nothing to set up.
	a := e.login("tina", "Tina-passw0rd")
	if a.Token == "" || a.TwoFactor != "" {
		t.Fatalf("login with policy off = %+v", a)
	}
	e.expect("POST", "/api/me/2fa/setup", a.Token, nil, http.StatusConflict)

	e.setPolicy(admin, "optional")
	a = e.login("tina", "Tina-passw0rd")
	if a.Token == "" || a.TwoFactor != "" {
		t.Fatalf("optional, not set up = %+v", a)
	}
	// A wrong code doesn't turn it on.
	e.expect("POST", "/api/me/2fa/setup", a.Token, nil, http.StatusOK)
	e.expect("POST", "/api/me/2fa/confirm", a.Token, map[string]string{"code": "000000"}, http.StatusBadRequest)
	e.waitAudit("two_factor.enable.failed", "invalid_code")
	secret, recovery, _ := e.enable(a.Token)
	e.waitAudit("two_factor.enable.success", "tina")
	// Every session of the account ended; the answer carried a new one.
	e.expect("GET", "/api/auth/me", a.Token, nil, http.StatusUnauthorized)

	// Stored encrypted.
	var enc string
	_ = e.db.Conn.QueryRow(`SELECT totp_secret_enc FROM users WHERE id = ?`, id).Scan(&enc)
	if enc == "" || strings.Contains(enc, secret) {
		t.Fatalf("secret stored as %q", enc)
	}

	// The password alone gives a challenge, not a session.
	a = e.login("tina", "Tina-passw0rd")
	if a.Token != "" || a.TwoFactor != "verify" || a.Challenge == "" {
		t.Fatalf("login with 2FA = %+v", a)
	}
	e.expect("GET", "/api/auth/me", a.Challenge, nil, http.StatusUnauthorized)
	out := e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": "123456"}, http.StatusUnauthorized)
	if !strings.Contains(out, "two_factor_invalid") {
		t.Fatal(out)
	}
	e.waitAudit("two_factor.verify.failed", "invalid_code")
	next := auth.TOTPCode(secret, time.Now().Add(30*time.Second)) // a step after the one confirm used
	var v loginAnswer
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": next}, http.StatusOK)), &v)
	if v.Token == "" {
		t.Fatalf("verify = %+v", v)
	}
	e.expect("GET", "/api/auth/me", v.Token, nil, http.StatusOK)
	e.waitAudit("two_factor.verify.success", `"two_factor_method":"totp"`)
	e.waitAudit("user.login.success", `"two_factor_method":"totp"`)
	// The challenge is used up, and the code works once.
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": next}, http.StatusUnauthorized)
	a = e.login("tina", "Tina-passw0rd")
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": next}, http.StatusUnauthorized)

	// A recovery code works once.
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": strings.ToUpper(recovery[0])}, http.StatusOK)), &v)
	if v.Token == "" || v.RecoveryCodesLeft == nil || *v.RecoveryCodesLeft != 9 {
		t.Fatalf("recovery verify = %+v", v)
	}
	e.waitAudit("two_factor.verify.success", `"recovery_codes_left":9`)
	a = e.login("tina", "Tina-passw0rd")
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": recovery[0]}, http.StatusUnauthorized)
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": "unknown", "code": recovery[1]}, http.StatusUnauthorized)

	// Off keeps what users set up; back on, it is asked again.
	e.setPolicy(admin, "off")
	if a = e.login("tina", "Tina-passw0rd"); a.Token == "" {
		t.Fatalf("policy off = %+v", a)
	}
	e.setPolicy(admin, "all")
	if a = e.login("tina", "Tina-passw0rd"); a.TwoFactor != "verify" {
		t.Fatalf("policy back on = %+v", a)
	}
	e.freshStep(id)
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": auth.TOTPCode(secret, time.Now())}, http.StatusOK)), &v)

	// New recovery codes need a code from the app; the old ones stop working.
	e.freshStep(id)
	e.expect("POST", "/api/me/2fa/recovery-codes", v.Token, map[string]string{"code": recovery[2]}, http.StatusBadRequest)
	var fresh struct{ RecoveryCodes []string }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/me/2fa/recovery-codes", v.Token, map[string]string{"code": auth.TOTPCode(secret, time.Now())}, http.StatusOK)), &fresh)
	if len(fresh.RecoveryCodes) != 10 {
		t.Fatal(fresh)
	}
	// Required for everyone: can't be turned off; optional: it can.
	e.expect("DELETE", "/api/me/2fa", v.Token, map[string]string{"code": fresh.RecoveryCodes[0]}, http.StatusForbidden)
	e.waitAudit("two_factor.disable.denied", "two_factor_required")
	e.setPolicy(admin, "optional")
	e.expect("DELETE", "/api/me/2fa", v.Token, map[string]string{"code": recovery[3]}, http.StatusBadRequest)
	e.expect("DELETE", "/api/me/2fa", v.Token, map[string]string{"code": fresh.RecoveryCodes[0]}, http.StatusOK)
	e.waitAudit("two_factor.disable.success", "recovery_code")
	if a = e.login("tina", "Tina-passw0rd"); a.Token == "" {
		t.Fatalf("after turning off = %+v", a)
	}

	// Never a code, a secret or a recovery code in the audit.
	time.Sleep(200 * time.Millisecond)
	rows, _ := e.db.Conn.Query(`SELECT resource_name || reason || details FROM audit_logs`)
	defer rows.Close()
	for rows.Next() {
		var text string
		_ = rows.Scan(&text)
		for _, s := range append([]string{secret, next, fresh.RecoveryCodes[1]}, recovery...) {
			if strings.Contains(strings.ToLower(text), strings.ToLower(s)) {
				t.Fatalf("audit holds %q: %s", s, text)
			}
		}
	}
}

// Wrong codes count as failed sign-ins, and a right password doesn't clear
// the count while the code is still to come.
func TestTwoFactorLockout(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.localUser("lou", "Lou-passw0rd", false)
	e.setPolicy(admin, "optional")
	e.enable(e.login("lou", "Lou-passw0rd").Token)
	for i := 0; i < 4; i++ {
		a := e.login("lou", "Lou-passw0rd")
		e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": "000000"}, http.StatusUnauthorized)
	}
	a := e.login("lou", "Lou-passw0rd")
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": "000000"}, http.StatusUnauthorized)
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": "000000"}, http.StatusTooManyRequests)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "lou", "password": "Lou-passw0rd"}, http.StatusTooManyRequests)
	e.waitAudit("two_factor.verify.locked", "too_many_failures")
}

// A required policy: the session of someone who hasn't set it up reaches only
// the set-up; the password change comes first; an admin reset ends sessions.
func TestTwoFactorEnrollment(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	bossID := e.localUser("boss", "Boss-passw0rd", true)
	e.localUser("joe", "Joe-passw0rd", false)
	e.grant(mustUserID(e, "joe"), [4]any{0, "team-a", "pods", "list"})
	// An open session isn't touched by a policy change.
	before := e.login("boss", "Boss-passw0rd").Token

	e.setPolicy(root, "admins")
	var s struct{ TwoFactorUnenrolled map[string]int }
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/session", root, nil, http.StatusOK)), &s)
	if s.TwoFactorUnenrolled["admins"] != 2 || s.TwoFactorUnenrolled["all"] != 3 {
		t.Fatalf("unenrolled = %+v", s)
	}
	e.expect("GET", "/api/admin/users", before, nil, http.StatusOK)

	// A non-admin isn't required under "admins".
	if a := e.login("joe", "Joe-passw0rd"); a.TwoFactor != "" || a.Token == "" {
		t.Fatalf("joe = %+v", a)
	}
	a := e.login("boss", "Boss-passw0rd")
	if a.TwoFactor != "enroll" || a.Token == "" {
		t.Fatalf("boss = %+v", a)
	}
	for _, p := range []string{"/api/admin/users", "/api/namespaces", "/api/features", "/api/me/api-keys"} {
		if out := e.expect("GET", p, a.Token, nil, http.StatusForbidden); !strings.Contains(out, "two_factor_enrollment_required") {
			t.Fatalf("%s = %s", p, out)
		}
	}
	e.expect("POST", "/api/ws-ticket", a.Token, map[string]string{"path": "/ws/events"}, http.StatusForbidden)
	if out := e.expect("GET", "/api/auth/me", a.Token, nil, http.StatusOK); !strings.Contains(out, `"enroll":true`) || !strings.Contains(out, `"required":true`) {
		t.Fatalf("me = %s", out)
	}
	// The password change is allowed (it comes first).
	e.expect("POST", "/api/auth/change-password", a.Token, map[string]string{"currentPassword": "Boss-passw0rd", "newPassword": "Boss-passw0rd-2"}, http.StatusOK)
	a = e.login("boss", "Boss-passw0rd-2")
	_, _, full := e.enable(a.Token)
	e.expect("GET", "/api/admin/users", full, nil, http.StatusOK)
	e.expect("GET", "/api/admin/users", a.Token, nil, http.StatusUnauthorized)
	if out := e.expect("GET", "/api/admin/users", root, nil, http.StatusOK); !strings.Contains(out, `"username":"boss"`) || !strings.Contains(out, `"twoFactorEnabled":true`) {
		t.Fatalf("users = %s", out)
	}

	// Admin reset: off, signed out, set up again on the next sign-in.
	e.expect("POST", "/api/admin/users/"+itoa(int64(bossID))+"/reset-2fa", root, nil, http.StatusOK)
	e.waitAudit("two_factor.reset.success", "boss")
	e.expect("GET", "/api/admin/users", full, nil, http.StatusUnauthorized)
	if a = e.login("boss", "Boss-passw0rd-2"); a.TwoFactor != "enroll" {
		t.Fatalf("after reset = %+v", a)
	}
	// Only an admin may reset.
	joe := e.login("joe", "Joe-passw0rd").Token
	e.expect("POST", "/api/admin/users/"+itoa(int64(bossID))+"/reset-2fa", joe, nil, http.StatusForbidden)
	e.waitAudit("two_factor.reset.denied", "admin_only")
	e.expect("PUT", "/api/admin/session", root, map[string]any{"twoFactorPolicy": "sometimes"}, http.StatusBadRequest)
}

func TestAzureRequireMFA(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	fakeEntra(t, e, func(code string) jwt.MapClaims {
		c := goodClaims(e, "jane@example.com")
		switch code {
		case "mfa":
			c["amr"] = []string{"pwd", "mfa"}
		case "pwd":
			c["amr"] = []string{"pwd"}
		}
		return c
	})
	cfg := map[string]any{
		"enabled": true, "tenantId": testTenant, "clientId": testClientID,
		"clientSecret": "s3cret", "redirectUrl": e.http.URL + "/api/auth/azure/callback",
	}
	e.expect("PUT", "/api/admin/azure-ad", admin, cfg, http.StatusOK)
	// Off: no amr needed.
	if code, _ := e.azureLogin("none", false); code != http.StatusOK {
		t.Fatalf("without the switch = %d", code)
	}
	cfg["requireMfa"], cfg["clientSecret"], cfg["passwordConfigured"] = true, "", true
	e.expect("PUT", "/api/admin/azure-ad", admin, cfg, http.StatusOK)
	if out := e.expect("GET", "/api/admin/azure-ad", admin, nil, http.StatusOK); !strings.Contains(out, `"requireMfa":true`) {
		t.Fatal(out)
	}
	for _, code := range []string{"none", "pwd"} {
		if status, _ := e.azureLogin(code, false); status != http.StatusFound {
			t.Fatalf("%s: %d, want the redirect to the sign-in page", code, status)
		}
	}
	e.waitAudit("user.login.denied", "azure_mfa_required")
	if code, _ := e.azureLogin("mfa", false); code != http.StatusOK {
		t.Fatalf("with mfa = %d", code)
	}
}

func mustUserID(e *testEnv, name string) int {
	u, err := e.store.GetUserByUsername(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.ID
}

// An LDAP account (here created on its first sign-in) gets the same code
// step and the same enrollment as a local one.
func TestTwoFactorLDAP(t *testing.T) {
	e := newTestEnv(t)
	srv := ldapfake.Start(t, ldapfake.Directory())
	_, root := e.user("root", true)
	e.expect("PUT", "/api/admin/ldap", root, map[string]any{
		"enabled": true, "url": srv.URL(), "timeoutSeconds": 5,
		"bindDn": ldapfake.ServiceDN, "bindPassword": ldapfake.ServicePwd,
		"userBaseDn": ldapfake.UsersDN, "userFilter": "(sAMAccountName=%s)", "usernameAttribute": "sAMAccountName",
		"autoProvision": true,
	}, http.StatusOK)
	e.setPolicy(root, "all")
	a := e.login("jo", ldapfake.JoPwd)
	if a.TwoFactor != "enroll" {
		t.Fatalf("first LDAP sign-in = %+v", a)
	}
	secret, _, _ := e.enable(a.Token)
	a = e.login("jo", ldapfake.JoPwd)
	if a.TwoFactor != "verify" {
		t.Fatalf("LDAP with 2FA = %+v", a)
	}
	e.expect("POST", "/api/auth/2fa/verify", "", map[string]string{"challenge": a.Challenge, "code": auth.TOTPCode(secret, time.Now().Add(30*time.Second))}, http.StatusOK)
	e.waitAudit("user.login.success", `"login_method":"ldap"`)
	// A wrong directory password still never reaches the code step.
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "jo", "password": ldapfake.JohnPwd}, http.StatusUnauthorized)
}
