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

// DefaultMinPasswordLength is the minimum length (in characters) of a local
// password unless PASSWORD_MIN_LENGTH says otherwise.
const DefaultMinPasswordLength = 8

// maxPasswordBytes: bcrypt ignores everything past 72 bytes, so a longer
// password would silently be truncated.
const maxPasswordBytes = 72

// CheckPasswordPolicy validates a new local password of at least minLength characters.
func CheckPasswordPolicy(password string, minLength int) error {
	if utf8.RuneCountInString(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password must not be blank")
	}
	return nil
}
