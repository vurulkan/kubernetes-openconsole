package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

const (
	testTenant   = "tenant-123"
	testClientID = "client-abc"
)

// fakeEntra stands in for login.microsoftonline.com: its token endpoint
// returns an ID token built from claimsFor(code).
func fakeEntra(t *testing.T, claimsFor func(code string) jwt.MapClaims) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+testTenant+"/oauth2/v2.0/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		idToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsFor(r.Form.Get("code"))).SignedString([]byte("k"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	}))
	t.Cleanup(srv.Close)
	prev := auth.AzureAuthority
	auth.AzureAuthority = srv.URL
	t.Cleanup(func() { auth.AzureAuthority = prev })
}

func goodClaims(username string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                auth.AzureAuthority + "/" + testTenant + "/v2.0",
		"aud":                testClientID,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": username,
		"oid":                "oid-" + username,
	}
}

// azureLogin runs start → callback without following redirects and returns
// the callback response.
func (e *testEnv) azureLogin(code string, tamperState bool) (int, string) {
	e.t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(e.http.URL + "/api/auth/azure/start")
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), auth.AzureAuthority+"/"+testTenant+"/oauth2/v2.0/authorize") {
		e.t.Fatalf("start = %d %s", resp.StatusCode, loc)
	}
	state := loc.Query().Get("state")
	if tamperState {
		state += "x"
	}
	req, _ := http.NewRequest("GET", e.http.URL+"/api/auth/azure/callback?code="+code+"&state="+url.QueryEscape(state), nil)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	cb, err := noRedirect.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer cb.Body.Close()
	body, _ := io.ReadAll(cb.Body)
	return cb.StatusCode, string(body)
}

func TestAzureADEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	fakeEntra(t, func(code string) jwt.MapClaims {
		c := goodClaims("jane@example.com")
		switch code {
		case "wrong-aud":
			c["aud"] = "someone-else"
		case "expired":
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		case "wrong-iss":
			c["iss"] = "https://evil.example/" + testTenant + "/v2.0"
		case "preexisting":
			c["preferred_username"] = "bob@example.com"
		case "other-oid":
			c["oid"] = "someone-else" // a re-created or renamed Entra user under jane's name
		case "no-oid":
			delete(c, "oid")
		}
		return c
	})
	e.expect("PUT", "/api/admin/azure-ad", admin, map[string]any{
		"enabled": true, "tenantId": testTenant, "clientId": testClientID,
		"clientSecret": "s3cret", "redirectUrl": e.http.URL + "/api/auth/azure/callback",
	}, http.StatusOK)

	// Happy path: the account is created and tagged as Azure AD.
	code, body := e.azureLogin("ok", false)
	if code != http.StatusOK || !strings.Contains(body, "authToken") {
		t.Fatalf("callback = %d %.200s", code, body)
	}
	u, err := e.store.GetUserByUsername(context.Background(), "jane@example.com")
	if err != nil || u.AuthSource != models.AuthSourceAzure || u.IsAdmin {
		t.Fatalf("jane = %+v, %v", u, err)
	}

	// Rejections.
	if code, _ := e.azureLogin("ok", true); code != http.StatusBadRequest {
		t.Fatalf("tampered state = %d, want 400", code)
	}
	for _, bad := range []string{"wrong-aud", "expired", "wrong-iss"} {
		if code, _ := e.azureLogin(bad, false); code != http.StatusUnauthorized {
			t.Fatalf("%s = %d, want 401", bad, code)
		}
	}

	// The account belongs to the Entra object that first signed in to it.
	if code, _ := e.azureLogin("other-oid", false); code != http.StatusForbidden {
		t.Fatalf("other oid = %d, want 403", code)
	}
	e.waitAudit("user.login.failed", "azure_oid_mismatch")
	if code, _ := e.azureLogin("no-oid", false); code != http.StatusForbidden {
		t.Fatalf("no oid = %d, want 403", code)
	}
	if code, _ := e.azureLogin("ok", false); code != http.StatusOK {
		t.Fatalf("jane again = %d", code)
	}

	// A local account with the same name is never taken over.
	bobID, _ := e.user("bob@example.com", false)
	if code, _ := e.azureLogin("preexisting", false); code != http.StatusForbidden {
		t.Fatalf("preexisting local = %d, want 403", code)
	}
	e.waitAudit("user.login.failed", "not_azure_account")
	if bob, _ := e.store.GetUserByID(context.Background(), bobID); bob.AuthSource != models.AuthSourceLocal {
		t.Fatalf("bob = %+v", bob)
	}
	// Azure AD accounts can't be given a local password.
	janeID := u.ID
	e.expect("POST", "/api/admin/users/"+itoa(int64(janeID))+"/reset-password", admin, map[string]string{"password": "New-passw0rd"}, http.StatusConflict)
}

// TestAzurePreCreatedByEmail: an account an admin pre-created under the
// person's e-mail is claimed on their first Microsoft sign-in even when
// preferred_username (the UPN) differs. Only unclaimed Azure AD accounts can
// be claimed this way.
func TestAzurePreCreatedByEmail(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, admin := e.user("root", true)
	gid, _ := e.store.CreateGroup(ctx, "payments")
	fakeEntra(t, func(code string) jwt.MapClaims {
		c := goodClaims("jdoe@corp.onmicrosoft.com")
		switch code {
		case "jane":
			c["email"] = "Jane.Doe@corp.com" // other case than the pre-created name
		case "mallory":
			c["preferred_username"] = "mallory@corp.onmicrosoft.com"
			c["oid"] = "oid-mallory"
			c["email"] = "jane.doe@corp.com" // same e-mail, after Jane claimed it
		case "local":
			c["preferred_username"] = "eve@corp.onmicrosoft.com"
			c["oid"] = "oid-eve"
			c["email"] = "ops@corp.com" // matches a local account
		}
		return c
	})
	e.expect("PUT", "/api/admin/azure-ad", admin, map[string]any{
		"enabled": true, "tenantId": testTenant, "clientId": testClientID,
		"clientSecret": "s3cret", "redirectUrl": e.http.URL + "/api/auth/azure/callback",
	}, http.StatusOK)
	e.expect("POST", "/api/admin/users", admin, map[string]any{
		"username": "jane.doe@corp.com", "source": "azure", "groupIds": []int{gid},
	}, http.StatusCreated)

	if code, body := e.azureLogin("jane", false); code != http.StatusOK {
		t.Fatalf("jane = %d %.200s", code, body)
	}
	jane, err := e.store.GetUserByUsername(ctx, "jane.doe@corp.com")
	if err != nil {
		t.Fatal(err)
	}
	if groups, _ := e.store.GetUserGroups(ctx, jane.ID); len(groups) != 1 {
		t.Fatalf("pre-created account lost its groups: %v", groups)
	}
	if _, err := e.store.GetUserByUsername(ctx, "jdoe@corp.onmicrosoft.com"); err == nil {
		t.Fatal("a second account was created instead of claiming the pre-created one")
	}
	e.waitAudit("user.login.success", `"linked_by":"email"`)

	// Already claimed: the same e-mail on another person gets a new account.
	if code, _ := e.azureLogin("mallory", false); code != http.StatusOK {
		t.Fatalf("mallory = %d", code)
	}
	if m, err := e.store.GetUserByUsername(ctx, "mallory@corp.onmicrosoft.com"); err != nil || m.ID == jane.ID {
		t.Fatalf("mallory = %+v, %v", m, err)
	}

	// A local account is never claimed by e-mail.
	opsID, _ := e.user("ops@corp.com", false)
	if code, _ := e.azureLogin("local", false); code != http.StatusOK {
		t.Fatalf("eve = %d", code)
	}
	if ops, _ := e.store.GetUserByID(ctx, opsID); ops.AuthSource != models.AuthSourceLocal {
		t.Fatalf("local account was claimed: %+v", ops)
	}
}
