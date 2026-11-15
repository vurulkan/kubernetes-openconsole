package backup_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/db"
)

func TestCreateListPruneOpen(t *testing.T) {
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Conn.Exec(`INSERT INTO groups (name) VALUES ('ops')`); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "backups")
	m := backup.New(d, dir, 2)
	ctx := context.Background()
	for _, tag := range []string{"a", "b", "c"} {
		if _, err := m.Create(ctx, tag); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("kept %d backups (%v), want 2", len(list), err)
	}
	st, _ := os.Stat(filepath.Join(dir, list[0].Name))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v, want 0600: it holds every credential", st.Mode().Perm())
	}

	// The copy is a working database with the data.
	copyDB, err := sql.Open("sqlite", filepath.Join(dir, list[0].Name))
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var n int
	if err := copyDB.QueryRow(`SELECT COUNT(*) FROM groups WHERE name = 'ops'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the copy has %d groups, %v", n, err)
	}

	f, info, err := m.Open(list[0].Name)
	if err != nil || info.SizeBytes == 0 {
		t.Fatalf("open: %v %+v", err, info)
	}
	f.Close()
	for _, bad := range []string{"../app.db", "app.db", list[0].Name + "/x"} {
		if _, _, err := m.Open(bad); !errors.Is(err, backup.ErrNotFound) {
			t.Errorf("Open(%q) = %v, want ErrNotFound", bad, err)
		}
	}
}

// An upgrade that changes the schema copies the database first; a start
// with nothing to change makes no copy.
func TestBackupBeforeUpgrade(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "app.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1,
		is_active INTEGER NOT NULL DEFAULT 1, is_admin INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	dir := filepath.Join(tmp, "backups")
	count := func() int {
		entries, _ := os.ReadDir(dir)
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "-pre-upgrade.db") {
				n++
			}
		}
		return n
	}
	d, err := db.OpenWithBackup(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if count() != 1 {
		t.Fatalf("%d pre-upgrade copies after the upgrade, want 1", count())
	}
	entries, _ := os.ReadDir(dir)
	if st, err := os.Stat(filepath.Join(dir, entries[0].Name())); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pre-upgrade copy mode %v (%v), want 0600: it holds every credential", st.Mode().Perm(), err)
	}
	d, err = db.OpenWithBackup(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if count() != 1 {
		t.Fatalf("%d pre-upgrade copies after a plain restart, want still 1", count())
	}
}

// A migration that fails stops the start and leaves the file as it was.
func TestFailedMigrationChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// A view named like a table the migration creates late (api_keys) makes
	// that CREATE TABLE fail after earlier ones (groups, …) have run.
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1, is_admin INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)`,
		`CREATE VIEW api_keys AS SELECT 1 AS id`,
	} {
		if _, err := legacy.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	legacy.Close()
	if d, err := db.Open(path); err == nil {
		d.Close()
		t.Fatal("opened a database whose migration fails")
	}
	check, _ := sql.Open("sqlite", path)
	defer check.Close()
	var tables, version int
	_ = check.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'groups'`).Scan(&tables)
	_ = check.QueryRow(`PRAGMA user_version`).Scan(&version)
	if tables != 0 || version != 0 {
		t.Fatalf("a failed migration left changes: groups table %d, user_version %d", tables, version)
	}
}
