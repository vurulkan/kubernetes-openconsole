package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	h := AuthMiddleware(secret, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
