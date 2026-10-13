package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

// TestLoginRespectsAuthSource: the account's source decides how a password
// is checked, and every successful sign-in is audited with its method.
func TestLoginRespectsAuthSource(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv := ldapfake.Start(t, ldapfake.Directory())
	_, admin := e.user("root", true)
	e.expect("PUT", "/api/admin/ldap", admin, map[string]any{
		"enabled": true, "url": srv.URL(), "timeoutSeconds": 5,
		"bindDn": ldapfake.ServiceDN, "bindPassword": ldapfake.ServicePwd,
		"userBaseDn": ldapfake.UsersDN, "userFilter": "(sAMAccountName=%s)", "usernameAttribute": "sAMAccountName",
	}, http.StatusOK)

	// account creates an active user with a known local password.
	account := func(name, source string) {
		t.Helper()
		id, _ := e.user(name, false)
		hash, _ := auth.HashPassword("Local-pass-1")
		if err := e.store.UpdateUserPassword(ctx, id, hash, false); err != nil {
			t.Fatal(err)
		}
		if err := e.store.SetUserAuthSource(ctx, id, source); err != nil {
			t.Fatal(err)
		}
	}
	login := func(user, pwd string, want int) string {
		t.Helper()
		return e.expect("POST", "/api/auth/login", "", map[string]string{"username": user, "password": pwd}, want)
	}

	// Local account: local password works.
	account("bob", models.AuthSourceLocal)
	login("bob", "Local-pass-1", http.StatusOK)
	e.waitAudit("login.success", "local")

	// LDAP account with a leftover local password: only the directory counts.
	account("jo", models.AuthSourceLDAP)
	login("jo", "Local-pass-1", http.StatusUnauthorized)
	login("jo", ldapfake.JoPwd, http.StatusOK)
	if a := e.waitAudit("login.success", "ldap"); a.User != "jo" {
		t.Fatalf("audit user = %q", a.User)
	}

	// Legacy import still tagged local: the directory password signs in and
	// tags the account LDAP.
	account("john", models.AuthSourceLocal)
	login("john", ldapfake.JohnPwd, http.StatusOK)
	if u, _ := e.store.GetUserByUsername(ctx, "john"); u.AuthSource != models.AuthSourceLDAP {
		t.Fatalf("john source = %q", u.AuthSource)
	}

	// Azure AD account: no password sign-in at all. The response is the
	// same as for a wrong password (no account / source disclosure); the
	// audit entry says why.
	account("jane@example.com", models.AuthSourceAzure)
	if out := login("jane@example.com", "Local-pass-1", http.StatusUnauthorized); strings.TrimSpace(out) != "" {
		t.Fatalf("azure password login body = %q", out)
	}
	e.waitAudit("login.failed", "azure_account")
}
