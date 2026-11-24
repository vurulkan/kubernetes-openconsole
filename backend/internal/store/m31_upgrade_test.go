package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"k8s-dashboard/backend/internal/models"
)

// 2.24 → 2.25: clusters are numbered in the order 2.24 showed them (default
// first, then by name) and the API key lifetime limit becomes required.
func TestClusterOrderAndKeyLimitUpgrade(t *testing.T) {
	for _, c := range []struct{ before, after int }{{0, 365}, {30, 30}, {3650, 3650}, {9999, 3650}} {
		path := filepath.Join(t.TempDir(), "app.db")
		conn, st := open(t, path)
		ctx := context.Background()
		creds := models.KubeCredentials{Method: "token", Server: "https://example.invalid", Token: []byte("x")}
		for _, name := range []string{"zeta", "beta", "alpha", "prod"} {
			if _, err := st.CreateCluster(ctx, name, "", creds); err != nil {
				t.Fatal(err)
			}
		}
		// What 2.24 left behind: no positions, a lifetime limit of any value, schema step 2.
		for _, stmt := range []string{
			`UPDATE clusters SET position = 0, is_active = (name = 'prod')`,
			`UPDATE session_settings SET api_key_max_days = ` + fmt.Sprint(c.before),
			`PRAGMA user_version = 2`,
		} {
			if _, err := conn.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
		conn.Close()

		conn, st = open(t, path)
		cs, err := st.ListClusters(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, cl := range cs {
			got = append(got, cl.Name)
		}
		if len(got) != 4 || got[0] != "prod" || got[1] != "alpha" || got[2] != "beta" || got[3] != "zeta" {
			t.Fatalf("order after upgrade = %v", got)
		}
		if ss, _ := st.GetSessionSettings(ctx); ss.APIKeyMaxDays != c.after {
			t.Fatalf("api_key_max_days %d → %d, want %d", c.before, ss.APIKeyMaxDays, c.after)
		}
		// The step ran once: a later admin order survives a restart.
		if err := st.SetClusterOrder(ctx, []int{cs[3].ID, cs[2].ID, cs[1].ID, cs[0].ID}); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		conn, st = open(t, path)
		if cs, _ := st.ListClusters(ctx); cs[0].Name != "zeta" {
			t.Fatalf("order not kept across a restart: %+v", cs)
		}
		// Added by 2.24 after a rollback (no position): listed last, like any new cluster.
		if _, err := conn.Exec(`INSERT INTO clusters (name, description, method, kubeconfig_enc, token_enc, server, ca_cert_enc, is_active) VALUES ('aaa', '', 'token', '', '', '', '', 0)`); err != nil {
			t.Fatal(err)
		}
		if cs, _ := st.ListClusters(ctx); cs[len(cs)-1].Name != "aaa" {
			t.Fatalf("a cluster without a position should come last: %+v", cs)
		}
		conn.Close()
	}
}
