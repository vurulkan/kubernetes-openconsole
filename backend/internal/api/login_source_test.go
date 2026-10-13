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

// TestCreateUserSources: admins can pre-create Azure AD accounts (no
// password, source azure) and put new users straight into groups.
func TestCreateUserSources(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, admin := e.user("root", true)
	gid, err := e.store.CreateGroup(ctx, "devs")
	if err != nil {
		t.Fatal(err)
	}

	e.expect("POST", "/api/admin/users", admin, map[string]any{
		"username": "jane@example.com", "source": "azure", "groupIds": []int{gid},
	}, http.StatusCreated)
	u, _ := e.store.GetUserByUsername(ctx, "jane@example.com")
	if u.AuthSource != models.AuthSourceAzure || u.MustChangePassword {
		t.Fatalf("azure user = %+v", u)
	}
	if groups, _ := e.store.GetUserGroups(ctx, u.ID); len(groups) != 1 {
		t.Fatalf("azure user groups = %v", groups)
	}
	e.waitAudit("admin.create", "source=azure")

	// Local users still need a password that meets the policy; LDAP users
	// are imported, not created.
	e.expect("POST", "/api/admin/users", admin, map[string]any{"username": "bob"}, http.StatusBadRequest)
	e.expect("POST", "/api/admin/users", admin, map[string]any{"username": "carl", "source": "ldap", "password": "Long-enough-1"}, http.StatusBadRequest)
	e.expect("POST", "/api/admin/users", admin, map[string]any{"username": "bob", "password": "Long-enough-1", "groupIds": []int{gid}}, http.StatusCreated)
	bob, _ := e.store.GetUserByUsername(ctx, "bob")
	if groups, _ := e.store.GetUserGroups(ctx, bob.ID); bob.AuthSource != models.AuthSourceLocal || len(groups) != 1 {
		t.Fatalf("bob = %+v groups=%v", bob, groups)
	}
}

// TestLDAPImportIntoGroups: imported users can land in groups right away,
// existing accounts are reported as skipped, and the audit names them.
func TestLDAPImportIntoGroups(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, admin := e.user("root", true)
	e.user("jo", false) // already exists
	gid, _ := e.store.CreateGroup(ctx, "devs")

	out := e.expect("POST", "/api/admin/ldap/users/import", admin, map[string]any{
		"usernames": []string{"john", "jo"}, "groupIds": []int{gid},
	}, http.StatusOK)
	if !strings.Contains(out, `"createdUsers":["john"]`) || !strings.Contains(out, `"skippedExisting":["jo"]`) {
		t.Fatalf("import = %s", out)
	}
	john, _ := e.store.GetUserByUsername(ctx, "john")
	if groups, _ := e.store.GetUserGroups(ctx, john.ID); john.AuthSource != models.AuthSourceLDAP || len(groups) != 1 {
		t.Fatalf("john = %+v groups=%v", john, groups)
	}
	e.waitAudit("admin.import", "1: john")
}

func TestVersionEndpointNeedsLogin(t *testing.T) {
	e := newTestEnv(t)
	_, bob := e.user("bob", false)
	e.expect("GET", "/api/version", "", nil, http.StatusUnauthorized)
	if out := e.expect("GET", "/api/version", bob, nil, http.StatusOK); !strings.Contains(out, `"version":"dev"`) {
		t.Fatalf("version = %s", out)
	}
}
