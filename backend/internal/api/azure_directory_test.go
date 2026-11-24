package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"k8s-dashboard/backend/internal/models"
)

// Sign-in finds the account by the Entra object id first: a UPN change keeps
// the person's account; two accounts on one oid (left by an older release)
// fall back to the name; a disabled account stays refused.
func TestAzureSignInByOIDFirst(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, admin := e.user("root", true)
	fakeEntra(t, e, func(code string) jwt.MapClaims {
		c := goodClaims(e, "jane@example.com") // oid-jane@example.com
		switch code {
		case "renamed":
			c["preferred_username"] = "jane.smith@example.com"
		case "renamed-again":
			c["preferred_username"] = "jane.s@example.com"
		}
		return c
	})
	e.expect("PUT", "/api/admin/azure-ad", admin, map[string]any{
		"enabled": true, "tenantId": testTenant, "clientId": testClientID,
		"clientSecret": "s3cret", "redirectUrl": e.http.URL + "/api/auth/azure/callback",
	}, http.StatusOK)
	if code, _ := e.azureLogin("ok", false); code != http.StatusOK {
		t.Fatalf("first sign-in = %d", code)
	}
	jane, _ := e.store.GetUserByUsername(ctx, "jane@example.com")

	// The UPN changed: same account, no second one.
	if code, _ := e.azureLogin("renamed", false); code != http.StatusOK {
		t.Fatalf("renamed = %d", code)
	}
	if _, err := e.store.GetUserByUsername(ctx, "jane.smith@example.com"); err == nil {
		t.Fatal("a UPN change created a second account")
	}
	e.waitAudit("user.login.success", `"linked_by":"oid"`)

	// Disabled: refused, and no empty new account under the new name.
	_ = e.store.UpdateUser(ctx, models.User{ID: jane.ID, Username: jane.Username, IsActive: false})
	if code, _ := e.azureLogin("renamed-again", false); code != http.StatusForbidden {
		t.Fatalf("disabled = %d, want 403", code)
	}
	if _, err := e.store.GetUserByUsername(ctx, "jane.s@example.com"); err == nil {
		t.Fatal("a disabled account's owner got a new account")
	}

	// Two accounts bound to the same oid (2.24 opened a second one after a
	// rename): the name decides, as before.
	_ = e.store.UpdateUser(ctx, models.User{ID: jane.ID, Username: jane.Username, IsActive: true})
	dupID, _ := e.store.CreateDirectoryUser(ctx, "jane.smith@example.com", "h", models.AuthSourceAzure, "oid-jane@example.com", nil)
	if code, _ := e.azureLogin("renamed", false); code != http.StatusOK {
		t.Fatalf("duplicate = %d", code)
	}
	logs := e.waitAudit("user.login.success", "")
	if logs.User != "jane.smith@example.com" {
		t.Fatalf("signed in as %q, want the account named like the sign-in (id %d)", logs.User, dupID)
	}
}

// fakeGraph stands in for Entra (client credentials) and Microsoft Graph.
type fakeGraph struct {
	tokenError string // OAuth error of the token endpoint
	status     int    // Graph's answer status (0 = 200)
}

func (f *fakeGraph) start(t *testing.T, e *testEnv) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/"+testTenant+"/oauth2/v2.0/token":
			_ = r.ParseForm()
			if f.tokenError != "" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenError, "error_description": "AADSTS7000215: Invalid client secret provided."})
				return
			}
			if r.Form.Get("grant_type") != "client_credentials" || !strings.HasSuffix(r.Form.Get("scope"), "/.default") {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token", "expires_in": 3600})
		case r.Header.Get("Authorization") != "Bearer graph-token":
			w.WriteHeader(http.StatusUnauthorized)
		case f.status != 0:
			w.WriteHeader(f.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
		case r.URL.Path == "/v1.0/users":
			if r.URL.Query().Get("$search") == "" { // the test button
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
				return
			}
			if r.Header.Get("ConsistencyLevel") != "eventual" || !strings.Contains(r.URL.Query().Get("$search"), `"userPrincipalName:ahmet"`) {
				http.Error(w, "bad search", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{
				{"id": "oid-ahmet", "displayName": "Ahmet Yılmaz", "mail": "ahmet@corp.com", "userPrincipalName": "ahmet@corp.com"},
				{"id": "oid-guest", "displayName": "Ahmet Guest", "mail": "ahmet@partner.com", "userPrincipalName": "ahmet_partner.com#EXT#@corp.onmicrosoft.com"},
				{"id": "oid-local", "displayName": "Ahmet Local", "mail": "", "userPrincipalName": "ahmet.local@corp.com"},
			}})
		case strings.HasPrefix(r.URL.Path, "/v1.0/users/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1.0/users/")
			users := map[string]map[string]string{
				"oid-ahmet": {"id": "oid-ahmet", "displayName": "Ahmet Yılmaz", "mail": "ahmet@corp.com", "userPrincipalName": "ahmet@corp.com"},
				"oid-guest": {"id": "oid-guest", "displayName": "Ahmet Guest", "mail": "ahmet@partner.com", "userPrincipalName": "ahmet_partner.com#EXT#@corp.onmicrosoft.com"},
				"oid-local": {"id": "oid-local", "displayName": "Ahmet Local", "userPrincipalName": "ahmet.local@corp.com"},
			}
			u, ok := users[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound", "message": "not found"}})
				return
			}
			_ = json.NewEncoder(w).Encode(u)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	e.server.SetAzureAuthority(srv.URL)
	e.server.graphURL = srv.URL
}

func TestAzureDirectorySearchAndImport(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, admin := e.user("root", true)
	_, bob := e.user("bob", false)
	e.user("ahmet.local@corp.com", false) // a local account with a directory person's name
	gid, _ := e.store.CreateGroup(ctx, "payments")
	f := &fakeGraph{}
	f.start(t, e)
	settings := map[string]any{
		"enabled": true, "tenantId": testTenant, "clientId": testClientID,
		"clientSecret": "s3cret", "redirectUrl": e.http.URL + "/api/auth/azure/callback",
	}
	e.expect("PUT", "/api/admin/azure-ad", admin, settings, http.StatusOK)

	// Off by default: the test works (to try before switching on), search doesn't.
	e.expect("POST", "/api/admin/azure-ad/graph/test", admin, nil, http.StatusOK)
	if out := e.expect("POST", "/api/admin/azure-ad/users/search", admin, map[string]string{"query": "ahmet"}, http.StatusBadRequest); !strings.Contains(out, "not_configured") {
		t.Fatalf("search while off = %s", out)
	}
	settings["graphSearch"] = true
	e.expect("PUT", "/api/admin/azure-ad", admin, settings, http.StatusOK)
	if got := e.expect("GET", "/api/admin/azure-ad", admin, nil, http.StatusOK); !strings.Contains(got, `"graphSearch":true`) {
		t.Fatalf("settings = %s", got)
	}

	e.expect("POST", "/api/admin/azure-ad/users/search", bob, map[string]string{"query": "ahmet"}, http.StatusForbidden)
	out := e.expect("POST", "/api/admin/azure-ad/users/search", admin, map[string]string{"query": `ahmet"`}, http.StatusOK)
	var found struct {
		Items []struct {
			ID, Username string
			Exists       bool
		}
	}
	_ = json.Unmarshal([]byte(out), &found)
	if len(found.Items) != 3 || found.Items[0].Username != "ahmet@corp.com" || found.Items[0].Exists ||
		found.Items[1].Username != "ahmet@partner.com" || !found.Items[2].Exists {
		t.Fatalf("search = %s", out)
	}
	e.noAudit("user.search")

	// Import: bound to the oid, in the group; an existing name is skipped.
	e.expect("POST", "/api/admin/azure-ad/users/import", bob, map[string]any{"ids": []string{"oid-ahmet"}}, http.StatusForbidden)
	e.waitAudit("user.import.denied", "admin_only")
	out = e.expect("POST", "/api/admin/azure-ad/users/import", admin, map[string]any{
		"ids": []string{"oid-ahmet", "oid-guest", "oid-local", "oid-gone"}, "groupIds": []int{gid},
	}, http.StatusOK)
	for _, want := range []string{
		`{"id":"oid-ahmet","username":"ahmet@corp.com","status":"created"}`,
		`{"id":"oid-guest","username":"ahmet@partner.com","status":"created"}`,
		`{"id":"oid-local","username":"ahmet.local@corp.com","status":"skipped","reason":"exists"}`,
		`{"id":"oid-gone","username":"oid-gone","status":"failed","reason":"not_found"}`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("import = %s, missing %s", out, want)
		}
	}
	e.waitAudit("user.import.success", `"account_source":"azure"`)
	ahmet, err := e.store.GetUserByUsername(ctx, "ahmet@corp.com")
	if err != nil || ahmet.AuthSource != models.AuthSourceAzure {
		t.Fatalf("ahmet = %+v, %v", ahmet, err)
	}
	if oid, _ := e.store.GetUserAzureOID(ctx, ahmet.ID); oid != "oid-ahmet" {
		t.Fatalf("oid = %q", oid)
	}
	if groups, _ := e.store.GetUserGroups(ctx, ahmet.ID); len(groups) != 1 {
		t.Fatalf("groups = %v", groups)
	}
	// Imported once: the same person (by oid) can't be imported again.
	out = e.expect("POST", "/api/admin/azure-ad/users/import", admin, map[string]any{"ids": []string{"oid-ahmet"}}, http.StatusOK)
	if !strings.Contains(out, `"status":"skipped"`) {
		t.Fatalf("second import = %s", out)
	}

	// Graph errors carry their reason code; the window is not stuck on them.
	f.status = http.StatusForbidden
	if out := e.expect("POST", "/api/admin/azure-ad/users/search", admin, map[string]string{"query": "ahmet"}, http.StatusBadGateway); !strings.Contains(out, "graph_forbidden") {
		t.Fatalf("403 = %s", out)
	}
	f.status = 0
	f.tokenError = "invalid_client"
	if out := e.expect("POST", "/api/admin/azure-ad/graph/test", admin, nil, http.StatusBadGateway); !strings.Contains(out, "graph_invalid_client") || !strings.Contains(out, "AADSTS7000215") {
		t.Fatalf("invalid client = %s", out)
	}
	e.server.graphURL = "http://127.0.0.1:1" // nothing listens
	f.tokenError = ""
	if out := e.expect("POST", "/api/admin/azure-ad/graph/test", admin, nil, http.StatusBadGateway); !strings.Contains(out, "graph_unreachable") {
		t.Fatalf("unreachable = %s", out)
	}
}
