package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

// The whole admin + user journey against a real (in-process) LDAP server:
// configure → test → search → import → sign in with the directory password.
func TestLDAPEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	srv := ldapfake.Start(t, ldapfake.Directory())
	_, admin := e.user("root", true)

	e.expect("PUT", "/api/admin/ldap", admin, map[string]any{
		"enabled":           true,
		"url":               srv.URL(),
		"timeoutSeconds":    5,
		"bindDn":            ldapfake.ServiceDN,
		"bindPassword":      ldapfake.ServicePwd,
		"userBaseDn":        ldapfake.UsersDN,
		"userFilter":        "(sAMAccountName=%s*)",
		"usernameAttribute": "sAMAccountName",
	}, http.StatusOK)
	// The bind password is stored encrypted and not echoed back.
	if out := e.expect("GET", "/api/admin/ldap", admin, nil, http.StatusOK); strings.Contains(out, ldapfake.ServicePwd) {
		t.Fatalf("bind password leaked: %s", out)
	}
	e.expect("POST", "/api/admin/ldap/test", admin, map[string]any{}, http.StatusOK)

	out := e.expect("POST", "/api/admin/ldap/users/search", admin, map[string]string{"query": "jo"}, http.StatusOK)
	if !strings.Contains(out, `"jo"`) || !strings.Contains(out, `"john"`) {
		t.Fatalf("search = %s", out)
	}

	// Not imported yet → can't sign in, even with the right password.
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "jo", "password": ldapfake.JoPwd}, http.StatusUnauthorized)

	e.expect("POST", "/api/admin/ldap/users/import", admin, map[string][]string{"usernames": {"jo"}}, http.StatusOK)
	out = e.expect("POST", "/api/auth/login", "", map[string]string{"username": "jo", "password": ldapfake.JoPwd}, http.StatusOK)
	if !strings.Contains(out, `"token"`) {
		t.Fatalf("login = %s", out)
	}
	if u, _ := e.store.GetUserByUsername(context.Background(), "jo"); u.AuthSource != models.AuthSourceLDAP {
		t.Fatalf("jo source = %q", u.AuthSource)
	}
	// Someone else's directory password never works for jo.
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "jo", "password": ldapfake.JohnPwd}, http.StatusUnauthorized)

	// Turning LDAP off stops directory sign-ins immediately.
	e.expect("PUT", "/api/admin/ldap", admin, map[string]any{"enabled": false, "url": srv.URL()}, http.StatusOK)
	e.expect("POST", "/api/auth/login", "", map[string]string{"username": "jo", "password": ldapfake.JoPwd}, http.StatusUnauthorized)
}
