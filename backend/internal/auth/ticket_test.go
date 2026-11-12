package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/models"
)

func TestTicketSingleUseAndPathBound(t *testing.T) {
	claims := &Claims{UserID: 7}
	id := IssueTicket(claims, "/ws/a")
	if _, ok := RedeemTicket(id, "/ws/b"); ok {
		t.Fatal("ticket accepted on another path")
	}
	if _, ok := RedeemTicket(id, "/ws/a"); ok {
		t.Fatal("ticket usable after a failed attempt")
	}

	id = IssueTicket(claims, "/ws/a")
	got, ok := RedeemTicket(id, "/ws/a")
	if !ok || got.UserID != 7 {
		t.Fatalf("redeem = %v, %v", got, ok)
	}
	if _, ok := RedeemTicket(id, "/ws/a"); ok {
		t.Fatal("ticket used twice")
	}

	id = IssueTicket(claims, "/ws/a")
	tickets.Lock()
	e := tickets.m[id]
	e.expires = time.Now().Add(-time.Second)
	tickets.m[id] = e
	tickets.Unlock()
	if _, ok := RedeemTicket(id, "/ws/a"); ok {
		t.Fatal("expired ticket accepted")
	}
}

func TestMiddlewareRejectsTokenInQuery(t *testing.T) {
	secret := []byte("k")
	jwt, _ := GenerateToken(secret, 1, "u", "", time.Minute)
	h := AuthMiddleware(secret, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/ws/events?token="+jwt, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("?token= accepted: %d", rec.Code)
	}
	id := IssueTicket(&Claims{UserID: 1}, "/ws/events")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/ws/events?ticket="+id, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket rejected: %d", rec.Code)
	}
}

type fakeKeys struct{ secret string }

func (f fakeKeys) AuthenticateKey(r *http.Request, secret string, keyID int) (*Claims, int) {
	if secret == f.secret || keyID == 7 {
		return &Claims{UserID: 1, APIKey: &models.APIKey{ID: 7}}, 0
	}
	return nil, http.StatusUnauthorized
}

// An oc_ bearer token goes to the key checker, never to the JWT parser; a
// ticket issued for a key is checked again when it is redeemed.
func TestMiddlewareAPIKeys(t *testing.T) {
	var got *Claims
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got, _ = FromContext(r.Context()) })
	serve := func(h http.Handler, req *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	withKey := func(k string) *http.Request {
		req := httptest.NewRequest("GET", "/api/x", nil)
		req.Header.Set("Authorization", "Bearer "+k)
		return req
	}
	off := AuthMiddleware([]byte("k"), nil, nil)(ok)
	if code := serve(off, withKey("oc_good")); code != http.StatusUnauthorized {
		t.Fatalf("keys off: %d", code)
	}
	on := AuthMiddleware([]byte("k"), nil, fakeKeys{secret: "oc_good"})(ok)
	if code := serve(on, withKey("oc_bad")); code != http.StatusUnauthorized {
		t.Fatalf("bad key: %d", code)
	}
	if code := serve(on, withKey("oc_good")); code != http.StatusOK || got.APIKey == nil {
		t.Fatalf("good key: %d %+v", code, got)
	}
	id := IssueTicket(got, "/ws/events")
	got = nil
	if code := serve(on, httptest.NewRequest("GET", "/ws/events?ticket="+id, nil)); code != http.StatusOK || got.APIKey == nil {
		t.Fatalf("key ticket: %d", code)
	}
	id = IssueTicket(&Claims{UserID: 1, APIKey: &models.APIKey{ID: 8}}, "/ws/events")
	if code := serve(on, httptest.NewRequest("GET", "/ws/events?ticket="+id, nil)); code != http.StatusUnauthorized {
		t.Fatalf("ticket of a key that is no longer valid: %d", code)
	}
}
