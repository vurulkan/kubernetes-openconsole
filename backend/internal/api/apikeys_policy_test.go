package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
)

// grantMode is grant with the role's API access mode set.
func (e *testEnv) grantMode(userID int, mode string, perms ...[4]any) int {
	e.t.Helper()
	id := e.grant(userID, perms...)
	if err := e.store.SetRoleAPIAccess(context.Background(), id, mode); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// resetKeyLimits lets a test call more often than a key may.
func (e *testEnv) resetKeyLimits() {
	e.server.keyLimits.mu.Lock()
	e.server.keyLimits.limiters = nil
	e.server.keyLimits.mu.Unlock()
}

// expectAll checks path → status for token (a 403 body must name the reason when one is given).
func (e *testEnv) expectAll(label, token string, want map[string]int, reason string) {
	e.t.Helper()
	e.resetKeyLimits()
	for path, code := range want {
		got, out := e.do("GET", path, token, nil)
		if got != code {
			e.t.Errorf("%s: GET %s = %d, want %d (%.120s)", label, path, got, code, out)
		}
		if got == http.StatusForbidden && reason != "" && strings.HasPrefix(path, "/api/namespaces/team-b") && !strings.Contains(out, reason) {
			e.t.Errorf("%s: GET %s body %q lacks %q", label, path, out, reason)
		}
	}
}

// The policy narrows a key on every call: each role's rows through its mode,
// the user's override over every mode; a key is never changed, so it works
// as before when the policy opens again (M15 decisions 1, 2, 5).
func TestAPIKeyPolicyModes(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	roleA := e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "secrets", "list"})
	roleB := e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-b", "pods", "list"}, [4]any{0, "team-b", "secrets", "list"})
	key, _ := e.createKey(bob, map[string]any{"name": "agent", "clusters": []int{0}, "allNamespaces": true, "grants": []string{"pods:list", "secrets:list"}})
	if err := e.store.SetRoleAPIAccess(context.Background(), roleB, rbac.AccessSafeRead); err != nil {
		t.Fatal(err)
	}

	byRoles := map[string]int{
		"/api/namespaces/team-a/secrets": 200, "/api/namespaces/team-b/secrets": 403,
		"/api/namespaces/team-a/pods": 200, "/api/namespaces/team-b/pods": 200, "/api/auth/me": 200,
	}
	e.expectAll("A full, B safe", key, byRoles, reasonAPIAccessPolicy)
	e.waitAudit("secret.list.denied", reasonAPIAccessPolicy)
	// The web session is never narrowed by the policy.
	e.expect("GET", "/api/namespaces/team-b/secrets", bob, nil, http.StatusOK)

	setOverride := func(o string) {
		t.Helper()
		e.expect("PUT", "/api/admin/users/"+itoa(int64(bobID)), admin,
			map[string]any{"username": "bob", "isActive": true, "apiAccessOverride": o}, http.StatusOK)
	}
	for _, c := range []struct {
		override string
		want     map[string]int
	}{
		{rbac.AccessSafeRead, map[string]int{"/api/namespaces/team-a/secrets": 403, "/api/namespaces/team-b/secrets": 403,
			"/api/namespaces/team-a/pods": 200, "/api/namespaces/team-b/pods": 200}},
		{rbac.AccessFull, map[string]int{"/api/namespaces/team-a/secrets": 200, "/api/namespaces/team-b/secrets": 200}},
		{rbac.AccessOff, map[string]int{"/api/namespaces/team-a/pods": 403, "/api/namespaces/team-b/pods": 403, "/api/auth/me": 403}},
		{"", byRoles},
	} {
		setOverride(c.override)
		e.expectAll("override "+c.override, key, c.want, "")
	}
	e.waitAudit("user.update", `"api_access":"off"`)
	e.waitAudit("api_key.use.denied", reasonAPIAccessOff)

	// The admin opens role B: the same key reaches B's secrets.
	e.expect("PUT", "/api/admin/roles/"+itoa(int64(roleB)), admin, map[string]any{"name": "team-b", "apiAccess": rbac.AccessFull}, http.StatusOK)
	e.waitAudit("role.update", `"api_access":"full"`)
	e.expectAll("B full", key, map[string]int{"/api/namespaces/team-b/secrets": 200}, "")
	e.expect("PUT", "/api/admin/roles/"+itoa(int64(roleB)), admin, map[string]any{"name": "team-b", "apiAccess": "everything"}, http.StatusBadRequest)

	// Every role off: the key is refused everywhere, with the reason.
	_ = e.store.SetRoleAPIAccess(context.Background(), roleA, rbac.AccessOff)
	_ = e.store.SetRoleAPIAccess(context.Background(), roleB, rbac.AccessOff)
	e.resetKeyLimits()
	if code, out := e.do("GET", "/api/auth/me", key, nil); code != 403 || !strings.Contains(out, reasonAPIAccessOff) {
		t.Fatalf("every role off: me = %d %s", code, out)
	}
	// One role back on: the key works again, within that role.
	_ = e.store.SetRoleAPIAccess(context.Background(), roleA, rbac.AccessSafeRead)
	e.expectAll("A safe, B off", key, map[string]int{"/api/namespaces/team-a/pods": 200, "/api/namespaces/team-a/secrets": 403,
		"/api/namespaces/team-b/pods": 403, "/api/auth/me": 200}, "")
}

// An admin's key: role modes don't apply; the override lowers it and takes
// the Admin API away (decision 3); clearing it gives everything back.
func TestAPIKeyPolicyAdmin(t *testing.T) {
	e := newTestEnv(t)
	rootID, root := e.user("root", true)
	key, _ := e.createKey(root, map[string]any{"name": "ops", "clusters": []int{0}, "allNamespaces": true,
		"grants": []string{"pods:list", "secrets:list"}, "adminScope": true})
	set := func(o string) {
		t.Helper()
		if err := e.store.SetUserAPIAccess(context.Background(), rootID, o); err != nil {
			t.Fatal(err)
		}
	}
	open := map[string]int{"/api/admin/users": 200, "/api/namespaces/team-a/secrets": 200, "/api/namespaces/team-a/pods": 200}
	e.expectAll("admin by roles", key, open, "")

	set(rbac.AccessSafeRead)
	e.expectAll("admin safe", key, map[string]int{"/api/admin/users": 403, "/api/namespaces/team-a/secrets": 403, "/api/namespaces/team-a/pods": 200}, "")
	e.expect("POST", "/api/me/api-keys", root, map[string]any{"name": "x", "clusters": []int{0}, "allNamespaces": true,
		"grants": []string{"pods:list"}, "adminScope": true}, http.StatusBadRequest)
	out := e.expect("GET", "/api/me/api-keys/ceiling", root, nil, http.StatusOK)
	if !strings.Contains(out, `"adminScopeAllowed":false`) || !strings.Contains(out, `"blocked":["pods:exec"`) {
		t.Fatalf("admin ceiling under safe read = %.400s", out)
	}

	set(rbac.AccessOff)
	e.expectAll("admin off", key, map[string]int{"/api/admin/users": 403, "/api/namespaces/team-a/pods": 403, "/api/auth/me": 403}, "")

	set(rbac.AccessFull)
	e.expectAll("admin full", key, open, "")
	set("")
	e.expectAll("admin back", key, open, "")
}

// The form's ceiling separates "you don't hold it" from "the policy keeps it
// from keys"; the key list flags cells the policy took away.
func TestAPIKeyPolicyCeiling(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	role := e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "pods", "exec"})
	e.createKey(bob, keyBody("shell", []string{"team-a"}, "pods:list", "pods:exec"))
	_ = e.store.SetRoleAPIAccess(context.Background(), role, rbac.AccessSafeRead)

	out := e.expect("GET", "/api/me/api-keys/ceiling", bob, nil, http.StatusOK)
	var c keyCeiling
	_ = json.Unmarshal([]byte(out), &c)
	if len(c.Namespaces) != 2 || len(c.SafeRead) == 0 || c.AdminScopeAllowed {
		t.Fatalf("ceiling = %+v", c)
	}
	for _, n := range c.Namespaces { // team-a on both clusters (a grant for every cluster)
		if strings.Join(n.Grants, ",") != "pods:list" || strings.Join(n.Blocked, ",") != "pods:exec" {
			t.Fatalf("ceiling namespace = %+v", n)
		}
	}
	e.expect("POST", "/api/me/api-keys", bob, keyBody("new", []string{"team-a"}, "pods:exec"), http.StatusBadRequest)
	out = e.expect("GET", "/api/me/api-keys", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"invalidGrants":["pods:exec"]`) {
		t.Fatalf("list should flag exec: %s", out)
	}
}

// The expiry policy holds for new and regenerated keys, never for keys that exist.
func TestAPIKeyExpiryPolicy(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	body := func(name string, exp any) map[string]any {
		b := keyBody(name, []string{"team-a"}, "pods:list")
		b["expiresAt"] = exp
		return b
	}
	forever, _ := e.createKey(bob, body("forever", nil))

	// A body without sessionMinutes keeps it.
	e.expect("PUT", "/api/admin/session", admin, map[string]any{"apiKeyMaxDays": 30, "apiKeyAllowNoExpiry": false}, http.StatusOK)
	if ss, _ := e.store.GetSessionSettings(context.Background()); ss.SessionMinutes != 60 || ss.APIKeyMaxDays != 30 || ss.APIKeyAllowNoExpiry {
		t.Fatalf("session settings = %+v", ss)
	}
	e.waitAudit("settings.update", "api_key_max_days=30")
	e.expect("PUT", "/api/admin/session", admin, map[string]any{"apiKeyMaxDays": -1}, http.StatusBadRequest)

	now := time.Now()
	e.expect("POST", "/api/me/api-keys", bob, body("a", nil), http.StatusBadRequest)
	e.expect("POST", "/api/me/api-keys", bob, body("b", now.AddDate(0, 0, 31)), http.StatusBadRequest)
	_, id := e.createKey(bob, body("c", now.AddDate(0, 0, 30)))
	path := "/api/me/api-keys/" + itoa(int64(id)) + "/regenerate"
	e.expect("POST", path, bob, map[string]any{"expiresAt": nil}, http.StatusBadRequest)
	e.expect("POST", path, bob, map[string]any{"expiresAt": now.AddDate(0, 0, 40)}, http.StatusBadRequest)
	e.expect("POST", path, bob, map[string]any{"expiresAt": now.AddDate(0, 0, 10)}, http.StatusOK)
	out := e.expect("GET", "/api/me/api-keys/ceiling", bob, nil, http.StatusOK)
	if !strings.Contains(out, `"maxDays":30,"allowNoExpiry":false`) {
		t.Fatalf("ceiling should carry the policy: %.300s", out)
	}

	// The key made before the policy keeps working and is listed for review.
	e.expect("GET", "/api/namespaces/team-a/pods", forever, nil, http.StatusOK)
	out = e.expect("GET", "/api/admin/api-keys", admin, nil, http.StatusOK)
	var list struct{ Items []adminAPIKeyView }
	_ = json.Unmarshal([]byte(out), &list)
	for _, k := range list.Items {
		if (k.Name == "forever") != k.OutsidePolicy {
			t.Errorf("%s outsidePolicy = %v", k.Name, k.OutsidePolicy)
		}
	}
}

func TestExpiryError(t *testing.T) {
	now := time.Now()
	at := func(d int) *time.Time { t := now.AddDate(0, 0, d); return &t }
	for _, c := range []struct {
		maxDays int
		never   bool
		t       *time.Time
		ok      bool
	}{
		{0, true, nil, true},
		{0, false, nil, false},
		{0, true, at(-1), false},
		{0, true, at(3650), true},
		{30, true, nil, true}, // the two settings are independent
		{30, false, at(30), true},
		{30, false, at(31), false},
	} {
		err := expiryError(models.SessionSettings{APIKeyMaxDays: c.maxDays, APIKeyAllowNoExpiry: c.never}, c.t, now)
		if (err == nil) != c.ok {
			t.Errorf("max %d never %v t %v: %v", c.maxDays, c.never, c.t, err)
		}
	}
}

// Admins list every key (no secret, no hash), revoke one with a comment or
// all of a user's; only on a web session; the owner's key then gets 401.
func TestAdminAPIKeys(t *testing.T) {
	e := newTestEnv(t)
	rootID, admin := e.user("root", true)
	bobID, bob := e.user("bob", false)
	e.grantMode(bobID, rbac.AccessFull, [4]any{0, "team-a", "pods", "list"}, [4]any{0, "team-a", "pods", "exec"})
	e.grant(bobID, [4]any{0, "team-b", "pods", "list"}, [4]any{0, "team-b", "pods", "exec"})
	k1, id1 := e.createKey(bob, keyBody("one", []string{"team-a"}, "pods:list"))
	k2, _ := e.createKey(bob, keyBody("two", []string{"team-a"}, "pods:list"))
	k3, _ := e.createKey(bob, keyBody("three", []string{"team-a"}, "pods:list"))
	adminKey, _ := e.createKey(admin, map[string]any{"name": "ops", "clusters": []int{0}, "allNamespaces": true, "grants": []string{"pods:list"}, "adminScope": true})

	out := e.expect("GET", "/api/admin/api-keys", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"owner":"bob"`) || strings.Contains(out, k1) || strings.Contains(out, hashAPIKey(k1)) || !strings.Contains(out, k1[:9]) {
		t.Fatalf("admin list = %.400s", out)
	}
	csv := e.expect("GET", "/api/admin/api-keys/export", admin, nil, http.StatusOK)
	if !strings.HasPrefix(csv, "owner,name,prefix,status") || strings.Contains(csv, k1) || !strings.Contains(csv, "bob,one,"+k1[:9]+",active") {
		t.Fatalf("csv = %s", csv)
	}
	e.waitAudit("api_key.export.success", "")

	// Never with a key, even an admin's with the Admin API scope; never for a non-admin.
	id := itoa(int64(id1))
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/admin/api-keys"}, {"GET", "/api/admin/api-keys/export"},
		{"POST", "/api/admin/api-keys/" + id + "/revoke"}, {"POST", "/api/admin/users/" + itoa(int64(bobID)) + "/revoke-api-keys"},
	} {
		e.expect(c.method, c.path, adminKey, map[string]any{}, http.StatusForbidden)
		e.expect(c.method, c.path, bob, map[string]any{}, http.StatusForbidden)
	}
	e.waitAudit("api_key.revoke.denied", reasonAPIKeyNotAllowed)

	e.expect("POST", "/api/admin/api-keys/"+id+"/revoke", admin, map[string]any{"comment": "left the team"}, http.StatusOK)
	e.expect("GET", "/api/namespaces/team-a/pods", k1, nil, http.StatusUnauthorized)
	l := e.waitAudit("api_key.revoke.success", `"by_admin":true`)
	if l.User != "root" || l.ResourceName != "one" || l.Details["owner"] != "bob" || l.Details["comment"] != "left the team" {
		t.Fatalf("revoke audit = %+v", l)
	}
	e.expect("POST", "/api/admin/api-keys/"+id+"/revoke", admin, nil, http.StatusConflict)
	e.expect("POST", "/api/admin/api-keys/999/revoke", admin, nil, http.StatusNotFound)

	// Preview: by roles (team-a full, team-b safe), an unsaved choice, the live keys.
	out = e.expect("GET", "/api/admin/users/"+itoa(int64(bobID))+"/api-access", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"namespace":"team-a","level":"all"`) || !strings.Contains(out, `"namespace":"team-b","level":"read"`) ||
		!strings.Contains(out, `"activeKeys":2`) || !strings.Contains(out, `"refused":false`) {
		t.Fatalf("preview = %s", out)
	}
	out = e.expect("GET", "/api/admin/users/"+itoa(int64(bobID))+"/api-access?override=off", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"refused":true`) || !strings.Contains(out, `"level":"none"`) {
		t.Fatalf("preview off = %s", out)
	}
	e.expect("GET", "/api/admin/users/"+itoa(int64(bobID))+"/api-access?override=nope", admin, nil, http.StatusBadRequest)
	out = e.expect("GET", "/api/admin/users/"+itoa(int64(rootID))+"/api-access?override=safe_read", admin, nil, http.StatusOK)
	if !strings.Contains(out, `"adminMode":"safe_read"`) {
		t.Fatalf("admin preview = %s", out)
	}

	out = e.expect("POST", "/api/admin/users/"+itoa(int64(bobID))+"/revoke-api-keys", admin, nil, http.StatusOK)
	if out != `{"revoked":2}`+"\n" {
		t.Fatalf("revoke all = %q", out)
	}
	e.waitAudit("api_key.revoke.success", `"all":true`)
	e.expect("GET", "/api/namespaces/team-a/pods", k2, nil, http.StatusUnauthorized)
	e.expect("GET", "/api/namespaces/team-a/pods", k3, nil, http.StatusUnauthorized)
}
