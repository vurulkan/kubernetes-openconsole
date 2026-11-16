package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Only HS256 tokens are accepted, even when another HMAC algorithm is signed
// with the right key.
func TestParseTokenOnlyHS256(t *testing.T) {
	secret := []byte("k")
	good, err := GenerateToken(secret, 1, "bob", "jti", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(secret, good); err != nil {
		t.Fatalf("HS256: %v", err)
	}
	claims := Claims{UserID: 1, Username: "bob", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	other, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(secret)
	if _, err := ParseToken(secret, other); err == nil {
		t.Fatal("HS512 token accepted")
	}
}
