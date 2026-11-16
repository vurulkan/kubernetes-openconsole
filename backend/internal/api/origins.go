package api

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	logpkg "k8s-dashboard/backend/internal/logging"
)

// allowedOrigins (ALLOWED_ORIGINS) are other sites whose pages may call the
// API from a browser. The console's own UI is same-origin and needs none;
// curl and agents send no Origin. Empty by default.
var allowedOrigins = map[string]bool{}

// wsOriginEnforce (WS_ORIGIN_CHECK=enforce) refuses a WebSocket whose Origin
// is another site; "warn" (default) only logs it.
var wsOriginEnforce bool

// SetOrigins parses ALLOWED_ORIGINS (comma-separated, e.g.
// https://tools.example.com) and WS_ORIGIN_CHECK (warn | enforce).
func SetOrigins(list, wsCheck string) error {
	m := map[string]bool{}
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		u, err := url.Parse(f)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.TrimSuffix(u.Path, "/") != "" {
			return fmt.Errorf("ALLOWED_ORIGINS: %q is not an origin like https://tools.example.com", f)
		}
		m[strings.ToLower(u.Scheme+"://"+u.Host)] = true
	}
	switch strings.ToLower(strings.TrimSpace(wsCheck)) {
	case "", "warn":
		wsOriginEnforce = false
	case "enforce":
		wsOriginEnforce = true
	default:
		return fmt.Errorf("WS_ORIGIN_CHECK: %q is not warn or enforce", wsCheck)
	}
	allowedOrigins = m
	return nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if origin := r.Header.Get("Origin"); origin != "" && allowedOrigins[strings.ToLower(origin)] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-OpenConsole-Cluster,X-OpenConsole-Refresh")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wsOriginOK is the CheckOrigin of every WebSocket upgrader. Accepted: no
// Origin (curl, agents), the request's own host (Host, or X-Forwarded-Host
// from a trusted proxy), ALLOWED_ORIGINS. Anything else is logged as
// ws.origin_mismatch and refused only with WS_ORIGIN_CHECK=enforce.
func wsOriginOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || allowedOrigins[strings.ToLower(origin)] {
		return true
	}
	if u, err := url.Parse(origin); err == nil && u.Host != "" {
		if strings.EqualFold(u.Host, r.Host) {
			return true
		}
		if fh := forwardedHost(r); fh != "" && strings.EqualFold(u.Host, fh) {
			return true
		}
	}
	slog.Warn("ws.origin_mismatch",
		slog.String("origin", origin),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.Bool("refused", wsOriginEnforce),
		slog.String("remote_ip", clientIP(r)),
		slog.String("request_id", logpkg.RequestIDFrom(r.Context())))
	return !wsOriginEnforce
}

// forwardedHost is X-Forwarded-Host when the connection comes from a trusted
// proxy (TRUSTED_PROXIES), else "".
func forwardedHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !isTrustedProxy(a) {
		return ""
	}
	v, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ",")
	return strings.TrimSpace(v)
}
