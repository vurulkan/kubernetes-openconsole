package api

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// handleEventsWS streams informer-driven ResourceEvents to the browser. The
// optional ?namespace=<ns> query param filters by namespace; cluster-scoped
// events (Namespace add/delete, cluster-level K8s Events) always pass through.
//
// Protocol: server pushes JSON-encoded kube.ResourceEvent frames; the client
// may send pings but does not need to send anything. The server pings every
// 25s to keep intermediaries from reaping idle sockets.
func (s *Server) handleEventsWS(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")

	bus := kubeFor(r).EventBus()
	if bus == nil {
		writeError(w, http.StatusServiceUnavailable, "event bus unavailable")
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sub := bus.Subscribe(ns)
	defer bus.Unsubscribe(sub)

	// Reader goroutine — surfaces client disconnects as context cancellation.
	// Also drains any pings/messages the client sends so WriteControl can see
	// pong replies.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.SetReadLimit(1024)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	pinger := time.NewTicker(25 * time.Second)
	defer pinger.Stop()

	ch := sub.Chan()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		case <-pinger.C:
			if err := conn.WriteControl(
				websocket.PingMessage,
				[]byte{},
				time.Now().Add(5*time.Second),
			); err != nil {
				return
			}
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}
}
