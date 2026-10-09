package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestActionCountersMove guards the /metrics counters that were declared but
// never incremented before 2.14.1.
func TestActionCountersMove(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	deploys := metricsStore.deployActionsTotal.Load()
	streams := metricsStore.wsLogStreamsStarted.Load()

	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusOK)
	if got := metricsStore.deployActionsTotal.Load(); got != deploys+1 {
		t.Fatalf("deployment actions = %d, want %d", got, deploys+1)
	}

	wsURL := "ws" + strings.TrimPrefix(e.http.URL, "http") + "/ws/namespaces/team-a/pods/api-1/logs"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": {"Bearer " + admin}})
	if err != nil {
		t.Fatalf("dial logs: %v", err)
	}
	conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for metricsStore.wsLogStreamsStarted.Load() != streams+1 {
		if time.Now().After(deadline) {
			t.Fatalf("log streams = %d, want %d", metricsStore.wsLogStreamsStarted.Load(), streams+1)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
