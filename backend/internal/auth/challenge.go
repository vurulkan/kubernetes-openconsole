package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// ChallengeTTL is how long the code step of a sign-in may take.
const ChallengeTTL = 5 * time.Minute

// A challenge is the half-done sign-in between the right password and the
// second-factor code: a random id held in memory (one replica), bound to the
// user, never a session. A wrong code leaves it alone (the login gate counts
// the failures); the right code ends it. A restart forgets them all: sign in again.
type challenge struct {
	userID  int
	expires time.Time
}

var challenges = struct {
	sync.Mutex
	m map[string]challenge
}{m: map[string]challenge{}}

// IssueChallenge starts the code step for userID.
func IssueChallenge(userID int) string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	now := time.Now()
	challenges.Lock()
	defer challenges.Unlock()
	for k, c := range challenges.m {
		if now.After(c.expires) {
			delete(challenges.m, k)
		}
	}
	challenges.m[id] = challenge{userID: userID, expires: now.Add(ChallengeTTL)}
	return id
}

// PeekChallenge returns the user of a live challenge.
func PeekChallenge(id string) (int, bool) {
	challenges.Lock()
	defer challenges.Unlock()
	c, ok := challenges.m[id]
	if !ok || time.Now().After(c.expires) {
		delete(challenges.m, id)
		return 0, false
	}
	return c.userID, true
}

// EndChallenge uses the challenge up.
func EndChallenge(id string) {
	challenges.Lock()
	delete(challenges.m, id)
	challenges.Unlock()
}
