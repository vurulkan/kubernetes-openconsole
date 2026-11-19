package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) as every authenticator app does it: HMAC-SHA1, 6 digits,
// 30 s steps, one step of clock drift either way.
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns 20 random bytes in base32, as authenticator apps take it.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// TOTPURI is the otpauth:// URI an authenticator app scans.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode is the code of one time step (RFC 4226 dynamic truncation).
func totpCode(key []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPCode is the app's code for secret at t (tests, scripts).
func TOTPCode(secret string, t time.Time) string {
	key, _ := b32.DecodeString(strings.ToUpper(secret))
	return totpCode(key, t.Unix()/totpPeriod, totpDigits)
}

// CheckTOTP returns the time step code matches, within one step of now, and
// only if that step is after lastStep: a code is accepted once, and never an
// older one after a newer one.
func CheckTOTP(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if err != nil || len(key) == 0 || len(code) != totpDigits {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step > lastStep && subtle.ConstantTimeCompare([]byte(totpCode(key, step, totpDigits)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// NewRecoveryCodes returns n one-time codes (50 random bits each, "xxxxx-xxxxx").
func NewRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		raw := make([]byte, 7)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		s := strings.ToLower(b32.EncodeToString(raw))[:10]
		codes[i] = s[:5] + "-" + s[5:]
	}
	return codes, nil
}

// HashRecoveryCode is what is stored of a recovery code: SHA-256 of its
// normalized form (the codes are random enough that a slow hash adds nothing).
func HashRecoveryCode(code string) string {
	c := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}
