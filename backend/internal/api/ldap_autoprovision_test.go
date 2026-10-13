package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

func TestLDAPAutoProvision(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv := ldapfake.Start(t, ldapfake.Directory())
	_, admin := e.user("root", true)
	gid, _ := e.store.CreateGroup(ctx, "readers")
	ldapCfg := func(auto bool) map[string]any {
		return map[string]any{
			"enabled": true, "url": srv.URL(), "timeoutSeconds": 5,
			"bindDn": ldapfake.ServiceDN, "bindPassword": ldapfake.ServicePwd,
			"userBaseDn": ldapfake.UsersDN, "userFilter": "(sAMAccountName=%s)", "usernameAttribute": "sAMAccountName",
			"autoProvision": auto, "autoProvisionGroupIds": []int{gid, 9999},
		}
	}
	login := func(user, pwd string, want int) {
		t.Helper()
		e.expect("POST", "/api/auth/login", "", map[string]string{"username": user, "password": pwd}, want)
	}
	noAccount := func(name string) {
		t.Helper()
		if _, err := e.store.GetUserByUsername(ctx, name); err == nil {
			t.Fatalf("account %q should not exist", name)
		}
	}

	// Off by default: a directory user without an account can't sign in.
	e.expect("PUT", "/api/admin/ldap", admin, ldapCfg(false), http.StatusOK)
	if out := e.expect("GET", "/api/admin/ldap", admin, nil, http.StatusOK); !strings.Contains(out, `"autoProvision":false`) {
		t.Fatalf("config = %s", out)
	}
	login("john", ldapfake.JohnPwd, http.StatusUnauthorized)
	noAccount("john")

	// On: the first sign-in creates an LDAP account in the configured
	// groups (unknown group ids are dropped).
	e.expect("PUT", "/api/admin/ldap", admin, ldapCfg(true), http.StatusOK)
	login("john", "wrong-password", http.StatusUnauthorized)
	noAccount("john")
	login("john", ldapfake.JohnPwd, http.StatusOK)
	john, err := e.store.GetUserByUsername(ctx, "john")
	if err != nil || john.AuthSource != models.AuthSourceLDAP || john.IsAdmin {
		t.Fatalf("john = %+v, %v", john, err)
	}
	if groups, _ := e.store.GetUserGroups(ctx, john.ID); len(groups) != 1 || groups[0] != gid {
		t.Fatalf("john groups = %v", groups)
	}
	e.waitAudit("user.auto_provision.success", "john")
	e.waitAudit("login.success", "ldap")

	// Another spelling signs in to the same account, no duplicate.
	login("JOHN", ldapfake.JohnPwd, http.StatusOK)
	noAccount("JOHN")

	// A disabled account is not re-created or re-enabled by signing in.
	e.expect("PUT", "/api/admin/users/"+itoa(int64(john.ID)), admin, map[string]any{"username": "john", "isActive": false, "isAdmin": false}, http.StatusOK)
	login("john", ldapfake.JohnPwd, http.StatusUnauthorized)
	users, _ := e.store.ListUsers(ctx)
	count := 0
	for _, u := range users {
		if strings.EqualFold(u.Username, "john") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("john accounts = %d", count)
	}
}
