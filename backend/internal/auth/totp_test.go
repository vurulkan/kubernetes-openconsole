package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 key "12345678901234567890"; the 6-digit code is
// the last six digits of the 8-digit one.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		if got := totpCode(key, v.unix/30, 8); got != v.code {
			t.Errorf("T=%d: got %s, want %s", v.unix, got, v.code)
		}
		if got := totpCode(key, v.unix/30, 6); got != v.code[2:] {
			t.Errorf("T=%d 6 digits: got %s, want %s", v.unix, got, v.code[2:])
		}
	}
}

func TestCheckTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b32.DecodeString(secret)
	now := time.Unix(1_700_000_000, 0)
	step := now.Unix() / 30
	for _, d := range []int64{-1, 0, 1} {
		if got, ok := CheckTOTP(secret, totpCode(key, step+d, 6), 0, now); !ok || got != step+d {
			t.Errorf("drift %d: got %d %v", d, got, ok)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := CheckTOTP(secret, totpCode(key, step+d, 6), 0, now); ok {
			t.Errorf("drift %d accepted", d)
		}
	}
	// Used once: the same step (or an older one) is refused afterwards.
	code := totpCode(key, step, 6)
	if _, ok := CheckTOTP(secret, code, step, now); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := CheckTOTP(secret, totpCode(key, step-1, 6), step, now); ok {
		t.Error("older code accepted after a newer one")
	}
	if _, ok := CheckTOTP(secret, "12345", 0, now); ok {
		t.Error("short code accepted")
	}
	if !strings.HasPrefix(TOTPURI("OpenConsole", "ali", secret), "otpauth://totp/OpenConsole:ali?") {
		t.Error("uri")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes(10)
	if err != nil || len(codes) != 10 {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Errorf("bad code %q", c)
		}
		seen[c] = true
	}
	if HashRecoveryCode(codes[0]) != HashRecoveryCode(" "+strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))) {
		t.Error("hash must ignore case, dashes and spaces")
	}
}

func TestChallenge(t *testing.T) {
	id := IssueChallenge(7)
	if uid, ok := PeekChallenge(id); !ok || uid != 7 {
		t.Fatal("peek")
	}
	if uid, ok := PeekChallenge(id); !ok || uid != 7 {
		t.Fatal("a wrong code doesn't use the challenge up")
	}
	EndChallenge(id)
	if _, ok := PeekChallenge(id); ok {
		t.Fatal("ended challenge still valid")
	}
	if _, ok := PeekChallenge("nope"); ok {
		t.Fatal("unknown challenge")
	}
}
