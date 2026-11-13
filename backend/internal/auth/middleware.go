package auth

import (
	"context"
	"encoding/json"
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

// APIKeyPrefix starts every API key secret, so secret scanners can spot one.
const APIKeyPrefix = "oc_"

// KeyAuthenticator checks an API key: the secret from the Authorization
// header, or (keyID > 0) the key a WebSocket ticket was issued with. A
// non-zero status rejects the request with that status (and the message, if any, as {"error": …}).
type KeyAuthenticator interface {
	AuthenticateKey(r *http.Request, secret string, keyID int) (*Claims, int, string)
}

// AuthMiddleware parses the JWT and, when a SessionValidator is wired, cross-
// checks the jti against the server-side session record so an admin can
// revoke a token before its natural expiry. Pre-tracking JWTs (no jti) and
// DB lookup failures are allowed through — rejecting on a transient DB blip
// would turn a storage glitch into a global logout. A bearer token starting
// with oc_ is an API key, checked by keys (nil = API keys are off).
func AuthMiddleware(secret []byte, sessions SessionValidator, keys KeyAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		serveKey := func(w http.ResponseWriter, r *http.Request, secret string, keyID int) {
			if keys == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			claims, status, message := keys.AuthenticateKey(r, secret, keyID)
			if status != 0 {
				if message != "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
					return
				}
				w.WriteHeader(status)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), claims)))
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token := ""
			if header != "" {
				parts := strings.SplitN(header, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					token = parts[1]
				}
			}
			var claims *Claims
			if strings.HasPrefix(token, APIKeyPrefix) {
				serveKey(w, r, token, 0)
				return
			} else if token != "" {
				parsed, err := ParseToken(secret, token)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				claims = parsed
			} else if id := r.URL.Query().Get("ticket"); id != "" {
				// WebSockets: the JWT never goes into a URL (see ticket.go).
				redeemed, ok := RedeemTicket(id, r.URL.Path)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if redeemed.APIKey != nil {
					// Checked again: the key may have been revoked since the ticket was issued.
					serveKey(w, r, "", redeemed.APIKey.ID)
					return
				}
				claims = redeemed
			} else {
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
