package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func setOriginsForTest(t *testing.T, list, ws, proxies string) {
	t.Helper()
	if err := SetOrigins(list, ws); err != nil {
		t.Fatal(err)
	}
	if err := SetTrustedProxies(proxies); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = SetOrigins("", "")
		_ = SetTrustedProxies("")
	})
}

func TestCORSOnlyAllowedOrigins(t *testing.T) {
	setOriginsForTest(t, "https://tools.example.com", "", "")
	h := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for origin, want := range map[string]string{
		"https://evil.example":      "",
		"https://tools.example.com": "https://tools.example.com",
		"":                          "",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Errorf("Origin %q: Allow-Origin = %q, want %q", origin, got, want)
		}
	}
}

func TestSetOriginsRejectsBadValues(t *testing.T) {
	t.Cleanup(func() { _ = SetOrigins("", "") })
	for _, c := range [][2]string{{"tools.example.com", ""}, {"https://x.example/path", ""}, {"", "block"}} {
		if err := SetOrigins(c[0], c[1]); err == nil {
			t.Errorf("SetOrigins(%q, %q) = nil, want error", c[0], c[1])
		}
	}
}

func TestWSOrigin(t *testing.T) {
	cases := []struct {
		name, origin, host, fwdHost, remote string
		enforce                            bool
		want                               bool
	}{
		{"no origin (curl)", "", "console.example", "", "203.0.113.5:1", true, true},
		{"same host", "https://console.example", "console.example", "", "203.0.113.5:1", true, true},
		{"other site, warn", "https://evil.example", "console.example", "", "203.0.113.5:1", false, true},
		{"other site, enforce", "https://evil.example", "console.example", "", "203.0.113.5:1", true, false},
		{"allow-listed", "https://tools.example.com", "console.example", "", "203.0.113.5:1", true, true},
		{"forwarded host from trusted proxy", "https://console.example", "10.0.0.7:8080", "console.example", "10.1.2.3:1", true, true},
		{"forwarded host from anyone else", "https://console.example", "10.0.0.7:8080", "console.example", "203.0.113.5:1", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode := "warn"
			if c.enforce {
				mode = "enforce"
			}
			setOriginsForTest(t, "https://tools.example.com", mode, "10.0.0.0/8")
			req := httptest.NewRequest(http.MethodGet, "/ws/events", nil)
			req.Host = c.host
			req.RemoteAddr = c.remote
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			if c.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", c.fwdHost)
			}
			if got := wsOriginOK(req); got != c.want {
				t.Errorf("wsOriginOK = %v, want %v", got, c.want)
			}
		})
	}
}
