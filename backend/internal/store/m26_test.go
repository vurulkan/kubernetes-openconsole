package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

// A COMMIT that fails (here SQLITE_BUSY: another connection reads, in the
// rollback-journal mode where that blocks a commit) must not leave the
// store's connection inside the transaction: before 2.23.1 every later
// write landed in it and was never committed ("cannot start a transaction
// within a transaction"), and was lost at the next restart.
func TestFailedCommitLeavesTheConnectionUsable(t *testing.T) {
	old := db.BusyTimeoutMS
	db.BusyTimeoutMS = 100
	t.Cleanup(func() { db.BusyTimeoutMS = old })
	path := filepath.Join(t.TempDir(), "app.db")
	conn, st := open(t, path)
	if _, err := conn.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	gid, _ := st.CreateGroup(ctx, "ops")
	rid, _ := st.CreateRole(ctx, "viewer", "")

	reader, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(100)")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rtx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := rtx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGroupRoles(ctx, gid, []int{rid}); err == nil {
		t.Fatal("commit should have failed while another connection reads")
	}
	_ = rtx.Rollback()

	if err := st.SetGroupRoles(ctx, gid, []int{rid}); err != nil {
		t.Fatalf("write after a failed commit: %v", err)
	}
	if err := reader.QueryRow(`SELECT COUNT(*) FROM group_roles WHERE group_id = ?`, gid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the write is not committed: %d rows, %v", n, err)
	}
}

// Foreign keys: unknown ids are refused and deletes cascade.
func TestForeignKeys(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()
	gid, _ := st.CreateGroup(ctx, "ops")
	rid, _ := st.CreateRole(ctx, "viewer", "")
	uid, _ := st.CreateUser(ctx, "alice", "hash")

	if err := st.SetGroupRoles(ctx, gid, []int{rid, 999}); !errors.Is(err, store.ErrUnknownReference) {
		t.Fatalf("unknown role: %v, want ErrUnknownReference", err)
	}
	if roles, _ := st.GetGroupRoles(ctx, gid); len(roles) != 0 {
		t.Fatalf("a failed SetGroupRoles changed the group: %v", roles)
	}
	if err := st.AddNamespacePermission(ctx, 999, 0, "team-a", "pods", "list"); !errors.Is(err, store.ErrUnknownReference) {
		t.Fatalf("permission of an unknown role: %v", err)
	}
	if err := st.SetUserGroups(ctx, uid, []int{gid}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGroupRoles(ctx, gid, []int{rid}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddNamespacePermission(ctx, rid, 0, "team-a", "pods", "list"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRole(ctx, rid); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGroup(ctx, gid); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM namespace_permissions`, `SELECT COUNT(*) FROM group_roles`, `SELECT COUNT(*) FROM user_groups`} {
		var n int
		if err := conn.QueryRow(q).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s = %d, %v: rows of a deleted role / group are left", q, n, err)
		}
	}
}

func newKey(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// Moving to an external key (ENCRYPTION_KEY_FILE), rotating it, and refusing
// to start with the wrong one.
func TestExternalEncryptionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	conn, st := open(t, path)
	ctx := context.Background()
	id, err := st.CreateCluster(ctx, "prod", "", models.KubeCredentials{Method: "token", Token: []byte("tok-123"), Server: "https://k"})
	if err != nil {
		t.Fatal(err)
	}
	var dbKey []byte
	if err := conn.QueryRow(`SELECT encryption_key FROM app_secrets WHERE id = 1`).Scan(&dbKey); err != nil || len(dbKey) != 32 {
		t.Fatalf("database key: %v", err)
	}
	dbSigning := st.SigningKey()

	token := func(st *store.Store) string {
		t.Helper()
		c, err := st.GetCluster(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return string(c.Credentials.Token)
	}
	raw := func() string {
		var v string
		_ = conn.QueryRow(`SELECT CAST(token_enc AS TEXT) FROM clusters WHERE id = ?`, id).Scan(&v)
		return v
	}

	k1 := newKey(t)
	st1, err := store.NewWithKeys(conn, store.Keys{Current: k1})
	if err != nil {
		t.Fatal(err)
	}
	if token(st1) != "tok-123" || !strings.HasPrefix(raw(), "v1:") {
		t.Fatalf("after the move: token %q, raw %q", token(st1), raw())
	}
	var n int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM app_secrets`).Scan(&n)
	if n != 0 {
		t.Fatal("the database key is still in the database")
	}
	if file, _ := os.ReadFile(path); bytes.Contains(file, dbKey) {
		t.Fatal("the old key's bytes are still in the file")
	}
	if bytes.Equal(st1.SigningKey(), dbSigning) || bytes.Equal(st1.SigningKey(), k1) {
		t.Fatal("the signing key must change and must not be the encryption key itself")
	}

	if _, err := store.New(conn); err == nil {
		t.Fatal("started without the external key")
	}
	k2 := newKey(t)
	before := raw()
	if _, err := store.NewWithKeys(conn, store.Keys{Current: k2}); err == nil {
		t.Fatal("started with another key and no ENCRYPTION_KEY_PREVIOUS")
	}
	if raw() != before {
		t.Fatal("a failed start changed the stored value")
	}

	st2, err := store.NewWithKeys(conn, store.Keys{Current: k2, Previous: k1})
	if err != nil {
		t.Fatal(err)
	}
	if token(st2) != "tok-123" || raw() == before {
		t.Fatalf("after the rotation: token %q, raw unchanged %v", token(st2), raw() == before)
	}
	if _, err := store.NewWithKeys(conn, store.Keys{Current: k2}); err != nil {
		t.Fatalf("restart after the rotation, previous key removed: %v", err)
	}
	if _, err := store.NewWithKeys(conn, store.Keys{Current: k2[:16]}); err == nil {
		t.Fatal("accepted a 16-byte key")
	}
}

// A value that can't be decrypted stops the move and changes nothing.
func TestExternalKeyMoveIsAllOrNothing(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()
	if _, err := st.CreateCluster(ctx, "a", "", models.KubeCredentials{Method: "token", Token: []byte("t1"), Server: "https://a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateCluster(ctx, "b", "", models.KubeCredentials{Method: "token", Token: []byte("t2"), Server: "https://b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE clusters SET token_enc = 'bm90IGVuY3J5cHRlZA==' WHERE name = 'b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewWithKeys(conn, store.Keys{Current: newKey(t)}); err == nil {
		t.Fatal("moved although one value can't be decrypted")
	}
	var prefixed, keys int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM clusters WHERE CAST(token_enc AS TEXT) LIKE 'v1:%'`).Scan(&prefixed)
	_ = conn.QueryRow(`SELECT COUNT(*) FROM app_secrets`).Scan(&keys)
	if prefixed != 0 || keys != 1 {
		t.Fatalf("half a move: %d values moved, %d database keys", prefixed, keys)
	}
}

// A key lost for good: with Lost the start goes on and the values it can't
// decrypt are emptied, so an admin can enter them again.
func TestLostEncryptionKey(t *testing.T) {
	conn, st := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()
	id, err := st.CreateCluster(ctx, "prod", "", models.KubeCredentials{Method: "token", Token: []byte("tok"), Server: "https://k"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewWithKeys(conn, store.Keys{Current: newKey(t)}); err != nil {
		t.Fatal(err)
	}
	fresh := newKey(t)
	if _, err := store.NewWithKeys(conn, store.Keys{Current: fresh}); err == nil {
		t.Fatal("started with a new key while values need the lost one")
	}
	st2, err := store.NewWithKeys(conn, store.Keys{Current: fresh, Lost: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := st2.GetCluster(ctx, id)
	if err != nil || len(c.Credentials.Token) != 0 || c.Server != "https://k" {
		t.Fatalf("after Lost: %+v, %v", c, err)
	}
	if _, err := store.NewWithKeys(conn, store.Keys{Current: fresh}); err != nil {
		t.Fatalf("restart without Lost: %v", err)
	}
}
