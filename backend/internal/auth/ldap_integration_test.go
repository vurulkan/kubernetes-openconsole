package auth

import (
	"strings"
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

// StartTLS checks the server's certificate against the host name in the URL
// and the configured CA; it no longer needs "skip verify" to work at all.
func TestLDAPStartTLSVerifiesCertificate(t *testing.T) {
	srv := ldapfake.StartTLS(t, ldapfake.Directory())
	cfg := fakeLDAPConfig(srv.URL(), "(sAMAccountName=%s)")
	cfg.StartTLS = true

	// Unknown CA: refused.
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unknown CA: %v", err)
	}
	// The CA configured: the certificate is checked and the bind works.
	cfg.CACert = srv.CAPEM
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err != nil {
		t.Fatalf("with CA: %v", err)
	}
	if err := TestConnection(cfg); err != nil {
		t.Fatalf("test connection with CA: %v", err)
	}
	// Host name not on the certificate: refused even with the CA.
	bad := cfg
	bad.URL = strings.Replace(srv.URL(), "127.0.0.1", "127.0.0.2", 1)
	if err := LDAPAuthenticate(bad, "jo", ldapfake.JoPwd); err == nil {
		t.Fatal("wrong host name accepted")
	}
	// Skip verify still works without a CA (the operator's explicit choice).
	cfg.CACert, cfg.SkipVerify = "", true
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err != nil {
		t.Fatalf("skip verify: %v", err)
	}
	cfg.CACert = "not a certificate"
	if err := LDAPAuthenticate(cfg, "jo", ldapfake.JoPwd); err == nil {
		t.Fatal("garbage CA accepted")
	}
}
