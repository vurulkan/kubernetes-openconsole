package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"

	"k8s-dashboard/backend/internal/models"
)

type Claims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	// APIKey is set when the request came with an API key instead of a web
	// session (never part of a JWT).
	APIKey *models.APIKey `json:"-"`
	// Idle is the inactivity timeout in seconds, so the browser can sign out
	// an idle screen by its own clock; the server enforces it in session_tokens.
	Idle int64 `json:"idle,omitempty"`
	// Cluster is the X-OpenConsole-Cluster value a WebSocket ticket carries
	// from the request that asked for it (never part of a JWT).
	Cluster string `json:"-"`
	jwt.RegisteredClaims
}

// GenerateToken signs a JWT with the given jti so the server can later look
// the session up in session_tokens and enforce revocation. jti may be empty
// for backward compat (tokens signed before session tracking landed).
func GenerateToken(secret []byte, userID int, username, jti string, ttl time.Duration) (string, error) {
	return GenerateSessionToken(secret, userID, username, jti, ttl, 0)
}

// GenerateSessionToken is GenerateToken with the inactivity timeout in the
// idle claim; ttl is the absolute limit.
func GenerateSessionToken(secret []byte, userID int, username, jti string, ttl, idle time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Idle:     int64(idle / time.Second),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func ParseToken(secret []byte, raw string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(raw, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
