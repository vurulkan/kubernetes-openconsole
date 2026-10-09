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

	// A pre-created local account is reused (keeping its groups) and tagged.
	bobID, _ := e.user("bob@example.com", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	if code, _ := e.azureLogin("preexisting", false); code != http.StatusOK {
		t.Fatalf("preexisting = %d", code)
	}
	bob, _ := e.store.GetUserByID(context.Background(), bobID)
	groups, _ := e.store.GetUserGroups(context.Background(), bobID)
	if bob.AuthSource != models.AuthSourceAzure || len(groups) != 1 {
		t.Fatalf("bob = %+v groups=%v", bob, groups)
	}
	// And can no longer be given a local password.
	e.expect("POST", "/api/admin/users/"+itoa(int64(bobID))+"/reset-password", admin, map[string]string{"password": "New-passw0rd"}, http.StatusConflict)
}
