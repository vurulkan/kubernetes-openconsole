package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/models"
)

// Admin → Backups: a copy holds every credential, so downloading is off
// unless BACKUP_ALLOW_DOWNLOAD=true (then older copies download too), and an
// API key never downloads one.
func TestBackupDownloadNeedsTheEnvSwitch(t *testing.T) {
	e := newTestEnv(t)
	m := backup.New(e.db, filepath.Join(e.tmp, "backups"), 3)
	e.server.SetBackups(m, 0, false)
	_, root := e.user("root", true)
	_, bob := e.user("bob", false)

	var made backup.Info
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/admin/backups", root, nil, http.StatusCreated)), &made)
	e.waitAudit("backup.create.success", made.Name)
	path := "/api/admin/backups/" + made.Name

	if out := e.expect("GET", path, root, nil, http.StatusForbidden); !strings.Contains(out, reasonBackupDownloadOff) {
		t.Fatalf("download while off: %s", out)
	}
	e.waitAudit("backup.download.denied", reasonBackupDownloadOff)
	e.expect("GET", path, bob, nil, http.StatusForbidden)

	e.server.SetBackups(m, 0, true) // BACKUP_ALLOW_DOWNLOAD=true after a restart
	if out := e.expect("GET", path, root, nil, http.StatusOK); !strings.HasPrefix(out, "SQLite format 3") {
		t.Fatalf("download is not the database: %.20q", out)
	}
	e.waitAudit("backup.download.success", made.Name)
	key, _ := e.createKey(root, map[string]any{"name": "admin-key", "clusters": []int{0}, "allNamespaces": true, "grants": []string{"pods:list"}, "adminScope": true})
	e.expect("GET", path, key, nil, http.StatusForbidden)
	e.expect("GET", path, bob, nil, http.StatusForbidden)
	e.expect("GET", "/api/admin/backups/app-20000101-000000.db", root, nil, http.StatusNotFound)

	var list struct {
		Items         []backup.Info
		AllowDownload bool
	}
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/backups", root, nil, http.StatusOK)), &list)
	if len(list.Items) != 1 || !list.AllowDownload {
		t.Fatalf("list = %+v", list)
	}
}

// With foreign keys, an id that doesn't exist is refused instead of being
// stored as a row that points nowhere.
func TestUnknownIDsAreRefused(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	bobID, _ := e.user("bob", false)
	roleID := e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	groups, _ := e.store.GetUserGroups(context.Background(), bobID)

	e.expect("POST", "/api/admin/roles/999/permissions", root,
		map[string]any{"namespace": "team-a", "resource": "pods", "action": "get"}, http.StatusNotFound)
	e.waitAudit("permission.create.failed", "not_found")
	e.expect("PUT", "/api/admin/groups/"+strconv.Itoa(groups[0])+"/roles", root, map[string]any{"roleIds": []int{roleID, 999}}, http.StatusBadRequest)
	e.expect("PUT", "/api/admin/users/"+strconv.Itoa(bobID)+"/groups", root, map[string]any{"groupIds": []int{999}}, http.StatusBadRequest)
	// Nothing changed.
	if roles, _ := e.store.GetGroupRoles(context.Background(), groups[0]); len(roles) != 1 || roles[0] != roleID {
		t.Fatalf("group roles after a refused change: %v", roles)
	}
	if g, _ := e.store.GetUserGroups(context.Background(), bobID); len(g) != 1 {
		t.Fatalf("user groups after a refused change: %v", g)
	}
}

// The audit list returns at most a page of 500; the CSV export streams every
// matching row up to 50 000 (it used to stop at 1 000 without saying so).
func TestAuditListAndExportLimits(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	stmt, err := e.db.Conn.Prepare(`INSERT INTO audit_logs (timestamp, user, action, verb, outcome, namespace, resource_type, resource_name)
		VALUES (?, 'x', 'pod.list', 'list', 'success', 'team-a', 'pod', '*')`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 1200; i++ {
		if _, err := stmt.Exec(now.Add(-time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()

	var page struct{ Items []models.AuditLog }
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/audit-logs?limit=-1&action=pod.list&actionExact=1", root, nil, http.StatusOK)), &page)
	if len(page.Items) != auditListMax {
		t.Fatalf("limit=-1 returned %d rows, want %d", len(page.Items), auditListMax)
	}
	csv := e.expect("GET", "/api/admin/audit-logs/export?action=pod.list&actionExact=1", root, nil, http.StatusOK)
	if lines := strings.Count(csv, "\n"); lines != 1201 {
		t.Fatalf("export has %d lines, want 1201 (header + every row)", lines)
	}
}

// A response that legitimately takes longer than the server's WriteTimeout
// (a command with a long timeout, a large download) reaches the client
// through the real middleware chain (otelhttp, requestLogger).
func TestExtendedWriteDeadline(t *testing.T) {
	slow := func(extend bool) http.Handler {
		return otelhttp.NewHandler(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if extend {
				extendWriteDeadline(w, 5*time.Second)
			}
			time.Sleep(600 * time.Millisecond)
			_, _ = w.Write([]byte("done"))
		})), "test")
	}
	for _, extend := range []bool{true, false} {
		srv := httptest.NewUnstartedServer(slow(extend))
		srv.Config.WriteTimeout = 300 * time.Millisecond
		srv.Start()
		res, err := http.Get(srv.URL)
		body := ""
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			body = string(b)
		}
		srv.Close()
		if extend && body != "done" {
			t.Fatalf("extended: body %q, err %v", body, err)
		}
		if !extend && body == "done" {
			t.Fatal("without the extension the write timeout did not apply; the test proves nothing")
		}
	}
}
