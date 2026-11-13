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
	jwt.RegisteredClaims
}

// GenerateToken signs a JWT with the given jti so the server can later look
// the session up in session_tokens and enforce revocation. jti may be empty
// for backward compat (tokens signed before session tracking landed).
func GenerateToken(secret []byte, userID int, username, jti string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		UserID:   userID,
		Username: username,
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
	})
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
