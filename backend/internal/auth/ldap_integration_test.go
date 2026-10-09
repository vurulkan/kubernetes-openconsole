package auth

import (
	"testing"

	"k8s-dashboard/backend/internal/testutil/ldapfake"
)

func fakeLDAPConfig(url, filter string) LDAPConfig {
	return LDAPConfig{
		Enabled:           true,
		URL:               url,
		TimeoutSeconds:    5,
		BindDN:            ldapfake.ServiceDN,
		BindPassword:      ldapfake.ServicePwd,
		UserBaseDN:        ldapfake.UsersDN,
		UserFilter:        filter,
		UsernameAttribute: "sAMAccountName",
	}
}

func TestLDAPAuthenticateAgainstDirectory(t *testing.T) {
	srv := ldapfake.Start(t, ldapfake.Directory())
	for _, filter := range []string{"(sAMAccountName=%s*)", "(sAMAccountName=%s)", "(&(objectClass=user)(sAMAccountName=%s*))"} {
		cfg := fakeLDAPConfig(srv.URL(), filter)
		if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err != nil {
			t.Errorf("%s: jo with his password: %v", filter, err)
		}
		if err := LDAPAuthenticate(cfg, "john", ldapfake.JohnPwd); err != nil {
			t.Errorf("%s: john with his password: %v", filter, err)
		}
		// The prefix-match hole: "jo" must never authenticate as john.
		if err := LDAPAuthenticate(cfg, "jo", ldapfake.JohnPwd); err == nil {
			t.Errorf("%s: jo authenticated with john's password", filter)
		}
		if err := LDAPAuthenticate(cfg, "jo", "wrong"); err == nil {
			t.Errorf("%s: wrong password accepted", filter)
		}
		if err := LDAPAuthenticate(cfg, "nobody", "x"); err == nil {
			t.Errorf("%s: unknown user accepted", filter)
		}
	}
	cfg := fakeLDAPConfig(srv.URL(), "(sAMAccountName=%s)")
	cfg.BindPassword = "bad"
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err == nil {
		t.Error("a broken service account must fail the login")
	}
	cfg = fakeLDAPConfig(srv.URL(), "(sAMAccountName=%s)")
	cfg.Enabled = false
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err == nil {
		t.Error("disabled LDAP must refuse")
	}
}

func TestLDAPSearchAndTestConnection(t *testing.T) {
	srv := ldapfake.Start(t, ldapfake.Directory())
	cfg := fakeLDAPConfig(srv.URL(), "(sAMAccountName=%s*)")
	users, err := SearchUsers(cfg, "jo")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, u := range users {
		got[u.Username] = true
	}
	if len(users) != 2 || !got["jo"] || !got["john"] {
		t.Fatalf("prefix search = %+v", users)
	}
	if err := TestConnection(cfg); err != nil {
		t.Fatalf("test connection: %v", err)
	}
	cfg.BindPassword = "bad"
	if err := TestConnection(cfg); err == nil {
		t.Fatal("test connection should fail with a bad bind password")
	}
}
