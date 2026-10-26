package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// TicketTTL is how long a WebSocket ticket can wait before it is used.
const TicketTTL = 30 * time.Second

// Browsers cannot set headers on a WebSocket, so the socket URL carries a
// ticket instead of the JWT: one use, 30 s, valid only for the path it was
// issued for. A ticket that ends up in an access log is worthless.
type ticket struct {
	claims  *Claims
	path    string
	expires time.Time
}

var tickets = struct {
	sync.Mutex
	m map[string]ticket
}{m: map[string]ticket{}}

// IssueTicket returns a single-use ticket for claims on path.
func IssueTicket(claims *Claims, path string) string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	now := time.Now()
	tickets.Lock()
	defer tickets.Unlock()
	for k, t := range tickets.m {
		if now.After(t.expires) {
			delete(tickets.m, k)
		}
	}
	tickets.m[id] = ticket{claims: claims, path: path, expires: now.Add(TicketTTL)}
	return id
}

// RedeemTicket consumes the ticket; it is gone after the first attempt, right path or not.
func RedeemTicket(id, path string) (*Claims, bool) {
	tickets.Lock()
	t, ok := tickets.m[id]
	delete(tickets.m, id)
	tickets.Unlock()
	if !ok || t.path != path || time.Now().After(t.expires) {
		return nil, false
	}
	return t.claims, true
}
