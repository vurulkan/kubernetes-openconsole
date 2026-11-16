package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Every admin write leaves one audit entry whatever its answer: success,
// denied (not an admin) or failed (with the answer's reason code). Before
// M29 most failure paths (delete user 404 / 409, delete group / role 500 …)
// wrote nothing.
func TestAdminWritesAuditEveryOutcome(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	_, bob := e.user("bob", false)
	var created struct{ ID int }
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/admin/groups", admin, map[string]any{"name": "ops"}, http.StatusCreated)), &created)
	group := itoa(int64(created.ID))
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/admin/roles", admin, map[string]any{"name": "viewer"}, http.StatusCreated)), &created)
	roleID := created.ID
	role := itoa(int64(roleID))
	_ = json.Unmarshal([]byte(e.expect("POST", "/api/admin/users", admin, map[string]any{"username": "carol", "password": "Carol-pass-1"}, http.StatusCreated)), &created)
	carol := itoa(int64(created.ID))

	type call struct {
		method, path string
		body         any
		status       int
		contains     string // in the name, reason or details
	}
	cases := []struct {
		action           string
		ok, fail, denied call
	}{
		{"user.create",
			call{"POST", "/api/admin/users", map[string]any{"username": "dave", "password": "Dave-pass-12"}, 201, "dave"},
			call{"POST", "/api/admin/users", map[string]any{"username": "eve", "password": "short"}, 400, "weak_password"},
			call{"POST", "/api/admin/users", map[string]any{"username": "x"}, 403, "admin_only"}},
		{"user.update",
			call{"PUT", "/api/admin/users/" + carol, map[string]any{"username": "carol", "isActive": true}, 200, "carol"},
			call{"PUT", "/api/admin/users/99999", map[string]any{"username": "nobody", "isActive": true}, 404, "not_found"},
			call{"PUT", "/api/admin/users/" + carol, map[string]any{"username": "carol"}, 403, "admin_only"}},
		{"user.delete",
			call{"DELETE", "/api/admin/users/" + carol, nil, 204, "carol"},
			call{"DELETE", "/api/admin/users/99999", nil, 404, "id:99999"},
			call{"DELETE", "/api/admin/users/1", nil, 403, "admin_only"}},
		{"group.update",
			call{"PUT", "/api/admin/groups/" + group, map[string]any{"name": "ops2"}, 200, "ops2"},
			call{"PUT", "/api/admin/groups/abc", map[string]any{"name": "x"}, 400, "invalid_id"},
			call{"PUT", "/api/admin/groups/" + group, map[string]any{"name": "x"}, 403, "admin_only"}},
		{"group.update",
			call{"PUT", "/api/admin/groups/" + group + "/roles", map[string]any{"roleIds": []int{roleID}}, 200, "roles"},
			call{"PUT", "/api/admin/groups/" + group + "/roles", map[string]any{"roleIds": []int{99999}}, 400, "not_found"},
			call{"PUT", "/api/admin/groups/" + group + "/roles", map[string]any{"roleIds": []int{}}, 403, "admin_only"}},
		{"role.update",
			call{"PUT", "/api/admin/roles/" + role, map[string]any{"name": "viewer2"}, 200, "viewer2"},
			call{"PUT", "/api/admin/roles/99999", map[string]any{"name": "ghost"}, 404, "not_found"},
			call{"PUT", "/api/admin/roles/" + role, map[string]any{"name": "x"}, 403, "admin_only"}},
		{"permission.create",
			call{"POST", "/api/admin/roles/" + role + "/permissions", map[string]any{"namespace": "team-a", "resource": "pods", "action": "list"}, 201, "pods:list"},
			call{"POST", "/api/admin/roles/99999/permissions", map[string]any{"namespace": "team-a", "resource": "pods", "action": "list"}, 404, "not_found"},
			call{"POST", "/api/admin/roles/" + role + "/permissions", map[string]any{}, 403, "admin_only"}},
		{"settings.update",
			call{"PUT", "/api/admin/session", map[string]any{"sessionMinutes": 30}, 200, "session_minutes=30"},
			call{"PUT", "/api/admin/session", map[string]any{"sessionMinutes": -1}, 400, "invalid_input"},
			call{"PUT", "/api/admin/session", map[string]any{"sessionMinutes": 30}, 403, "admin_only"}},
		{"group.delete",
			call{"DELETE", "/api/admin/groups/" + group, nil, 204, "ops2"},
			call{"DELETE", "/api/admin/groups/abc", nil, 400, "invalid_id"},
			call{"DELETE", "/api/admin/groups/" + group, nil, 403, "admin_only"}},
		{"role.delete",
			call{"DELETE", "/api/admin/roles/" + role, nil, 204, "viewer2"},
			call{"DELETE", "/api/admin/roles/abc", nil, 400, "invalid_id"},
			call{"DELETE", "/api/admin/roles/" + role, nil, 403, "admin_only"}},
	}
	for _, c := range cases {
		e.expect(c.denied.method, c.denied.path, bob, c.denied.body, c.denied.status)
		e.waitAudit(c.action+".denied", c.denied.contains)
		e.expect(c.fail.method, c.fail.path, admin, c.fail.body, c.fail.status)
		e.waitAudit(c.action+".failed", c.fail.contains)
		e.expect(c.ok.method, c.ok.path, admin, c.ok.body, c.ok.status)
		e.waitAudit(c.action+".success", c.ok.contains)
	}
}
