package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

type contextKey string

const userContextKey contextKey = "user"

func WithUser(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, userContextKey, claims)
}

func FromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(userContextKey).(*Claims)
	return claims, ok
}

// SessionValidator decides whether a parsed JWT's jti is still live. Returning
// (false, nil) means "revoked or expired per the server-side session record",
// which is distinct from a transport error. A nil validator disables
// server-side revocation (useful in tests).
type SessionValidator interface {
	// Validate returns live=true if the session is accepted. ok=false means
	// explicitly rejected; err means lookup failed (treated as fail-open by
	// the middleware so a DB blip doesn't log everyone out).
	Validate(ctx context.Context, jti string) (live bool, err error)
	// Touch bumps last_used_at; non-blocking.
	Touch(jti string)
}

// AuthMiddleware parses the JWT and, when a SessionValidator is wired, cross-
// checks the jti against the server-side session record so an admin can
// revoke a token before its natural expiry. Pre-tracking JWTs (no jti) and
// DB lookup failures are allowed through — rejecting on a transient DB blip
// would turn a storage glitch into a global logout.
func AuthMiddleware(secret []byte, sessions SessionValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token := ""
			if header != "" {
				parts := strings.SplitN(header, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					token = parts[1]
				}
			}
			if token == "" {
				token = r.URL.Query().Get("token")
			}
			if token == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			claims, err := ParseToken(secret, token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if sessions != nil && claims.ID != "" {
				live, lookupErr := sessions.Validate(r.Context(), claims.ID)
				if lookupErr != nil {
					slog.Warn("session lookup failed; allowing", "error", lookupErr.Error())
				} else if !live {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				sessions.Touch(claims.ID)
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), claims)))
		})
	}
}
