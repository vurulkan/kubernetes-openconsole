package store_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"k8s-dashboard/backend/internal/models"
)

// A base DN holds commas of its own; the list is stored one DN per line.
func TestLDAPBaseDNsKeepTheirCommas(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()
	want := []string{"OU=Users,DC=example,DC=corp", "OU=Admins,DC=example,DC=corp"}
	if err := st.UpdateLDAPConfig(ctx, models.LDAPConfig{UserBaseDNs: want}); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.GetLDAPConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.UserBaseDNs, want) {
		t.Fatalf("got %q", cfg.UserBaseDNs)
	}

	// A value saved by 2.23.0 (joined with commas) reads back as one DN.
	if _, err := conn.Exec(`UPDATE ldap_config SET user_base_dns = 'OU=Users,DC=example,DC=corp' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = st.GetLDAPConfig(ctx); !reflect.DeepEqual(cfg.UserBaseDNs, []string{"OU=Users,DC=example,DC=corp"}) {
		t.Fatalf("old value: got %q", cfg.UserBaseDNs)
	}
}
