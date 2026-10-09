package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

// TestExecBridgeConcurrentWrites drives stdout writes and control-frame writes
// (what the idle watchdog sends) at the same time. gorilla panics on
// overlapping writes, so before writes were serialized this test crashed.
func TestExecBridgeConcurrentWrites(t *testing.T) {
	serverConn := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		serverConn <- c
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn := <-serverConn
	defer conn.Close()

	// Drain the client side so server writes never block on a full buffer.
	frames := make(chan int, 1)
	go func() {
		n := 0
		for {
			if _, _, err := client.ReadMessage(); err != nil {
				frames <- n
				return
			}
			n++
		}
	}()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newExecBridge(conn, cancel, nil)
	defer b.Close()

	const perWriter = 500
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := b.Write([]byte("output chunk\r\n")); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				b.writeError("session idle timeout")
			}
		}()
	}
	wg.Wait()
	conn.Close()
	if got, want := <-frames, 8*perWriter; got != want {
		t.Fatalf("client received %d frames, want %d", got, want)
	}
}
