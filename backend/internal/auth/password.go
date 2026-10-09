package auth

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func ComparePassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MinPasswordLength is the minimum length (in characters) for passwords set
// on local accounts. Configured from PASSWORD_MIN_LENGTH at startup.
var MinPasswordLength = 8

// maxPasswordBytes: bcrypt ignores everything past 72 bytes, so a longer
// password would silently be truncated.
const maxPasswordBytes = 72

// CheckPasswordPolicy validates a new local password.
func CheckPasswordPolicy(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password must not be blank")
	}
	return nil
}
