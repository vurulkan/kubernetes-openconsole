package api

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s-dashboard/backend/internal/models"
)

// A token-only edit keeps the stored CA (the API server's certificate didn't
// change); removeCaCert drops it on purpose.
func TestClusterTokenEditKeepsStoredCA(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"NamespaceList","apiVersion":"v1","items":[]}`))
	}))
	defer apiServer.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: apiServer.Certificate().Raw})
	id, err := e.store.CreateCluster(context.Background(), "private-ca", "", models.KubeCredentials{
		Method: "token", Server: apiServer.URL, Token: []byte("old"), CACert: ca,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/admin/clusters/%d", id)
	edit := map[string]any{"name": "private-ca", "method": "token", "replaceSecrets": true, "server": apiServer.URL, "token": "new"}

	e.expect("PUT", path, admin, edit, http.StatusOK)
	c, err := e.store.GetCluster(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Credentials.Token) != "new" || string(c.Credentials.CACert) != string(ca) {
		t.Fatalf("token %q, CA kept %v", c.Credentials.Token, string(c.Credentials.CACert) == string(ca))
	}

	// Without the CA the server's certificate can't be verified: refused, nothing changes.
	edit["removeCaCert"] = true
	out := e.expect("PUT", path, admin, edit, http.StatusBadRequest)
	if !strings.Contains(out, "certificate") {
		t.Fatalf("want a certificate error, got %s", out)
	}
	if c, _ = e.store.GetCluster(context.Background(), id); string(c.Credentials.CACert) != string(ca) {
		t.Fatal("a refused edit changed the stored CA")
	}
}

// The fonts ship with the UI: the policy allows no font CDN.
func TestCSPAllowsNoFontCDN(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Get(e.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" || strings.Contains(csp, "fonts.g") || !strings.Contains(csp, "font-src 'self' data:") {
		t.Fatalf("CSP: %q", csp)
	}
}
