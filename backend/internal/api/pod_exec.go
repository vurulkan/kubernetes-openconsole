package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// Default shells tried in order when the client did not pick one.
var defaultShells = []string{"/bin/bash", "/bin/sh", "/bin/ash"}

// Max idle time with no stdin before we close an exec session.
const execIdleTimeout = 5 * time.Minute

// Client → Server control messages are JSON text frames of this shape;
// stdin lives in binary frames to keep it opaque to transit.
type execControl struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// handlePodExecWS opens a WebSocket, authenticates the user, verifies the
// pods:exec permission and bridges to the Kubernetes exec SPDY stream.
func (s *Server) handlePodExecWS(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	pod := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), claims.UserID, namespace, "pods", "exec") {
		s.recordExecAudit(claims.Username, namespace, pod, "denied", "", requestID)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	container := strings.TrimSpace(r.URL.Query().Get("container"))
	command := strings.TrimSpace(r.URL.Query().Get("command"))
	if command == "" {
		command = "auto"
	}

	client, ok := s.kube.Client()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	cfg, ok := s.kube.RESTConfig()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("exec ws upgrade failed", slog.Any("error", err), slog.String("request_id", requestID))
		return
	}
	defer conn.Close()

	req := client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   splitCommand(command),
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		writeExecError(conn, "spdy init failed: "+err.Error())
		s.recordExecAudit(claims.Username, namespace, pod, "failed", "spdy_init:"+err.Error(), requestID)
		return
	}

	start := time.Now()
	s.recordExecAudit(claims.Username, namespace, pod, "start",
		"container="+container+";cmd="+command, requestID)
	slog.Info("pod.exec.start",
		slog.String("user", claims.Username),
		slog.String("namespace", namespace),
		slog.String("pod", pod),
		slog.String("container", container),
		slog.String("command", command),
		slog.String("request_id", requestID),
	)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	bridge := newExecBridge(conn, cancel)
	defer bridge.Close()

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             bridge,
		Stdout:            bridge,
		Stderr:            bridge,
		Tty:               true,
		TerminalSizeQueue: bridge,
	})

	outcome := "end"
	detail := ""
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		outcome = "failed"
		detail = err.Error()
		writeExecError(conn, "exec ended: "+err.Error())
	}
	duration := time.Since(start)
	s.recordExecAudit(claims.Username, namespace, pod, outcome,
		detail+";dur_ms="+itoa(duration.Milliseconds()), requestID)
	slog.Info("pod.exec.end",
		slog.String("user", claims.Username),
		slog.String("namespace", namespace),
		slog.String("pod", pod),
		slog.String("outcome", outcome),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.String("request_id", requestID),
	)
}

// splitCommand resolves the client-supplied command into an argv slice for
// PodExecOptions. The special token "auto" asks the pod to try bash, then
// ash, then sh — the first shell that exists wins. We also export a sensible
// PS1 so the operator sees `user@host:/path$` instead of an empty prompt in
// containers that ship without /etc/profile or /root/.bashrc (very common).
// Any other value is split on whitespace, so callers can pass "/bin/bash",
// "/bin/ash", "/bin/sh", or a richer "sh -c '…'" string if they really need it.
func splitCommand(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || strings.EqualFold(cmd, "auto") {
		return []string{
			"/bin/sh", "-c",
			`export PS1='\u@\h:\w\$ ';` +
				` export TERM=xterm-256color;` +
				` if command -v bash >/dev/null 2>&1; then exec bash --norc -i;` +
				` elif command -v ash >/dev/null 2>&1; then exec ash;` +
				` else exec sh; fi`,
		}
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return []string{"/bin/sh"}
	}
	return parts
}

func writeExecError(conn *websocket.Conn, msg string) {
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","message":`+jsonString(msg)+`}`))
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func itoa(v int64) string {
	// Minimal avoiding another import; strconv already present elsewhere but
	// this file would import more surface. Keep it local.
	if v == 0 {
		return "0"
	}
	return formatInt(v)
}

func formatInt(v int64) string {
	negative := v < 0
	if negative {
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// recordExecAudit writes an audit row and keeps the console log aligned.
func (s *Server) recordExecAudit(user, namespace, pod, outcome, detail, requestID string) {
	resource := pod
	if detail != "" {
		resource = pod + " (" + detail + ")"
	}
	go s.audit.Record(context.Background(), models.AuditLog{
		User:         user,
		Action:       "pod.exec." + outcome,
		Namespace:    namespace,
		ResourceType: "pod",
		ResourceName: resource,
	})
	_ = requestID
}

// execBridge wires a WebSocket conn to the io.Reader / io.Writer /
// remotecommand.TerminalSizeQueue expected by remotecommand.StreamOptions.
// It also enforces the exec idle timeout and surfaces resize messages.
type execBridge struct {
	conn   *websocket.Conn
	cancel context.CancelFunc

	// stdin: binary WS frames from the client; served to Read().
	stdinCh chan []byte

	// resize queue plumbing.
	sizeCh chan *remotecommand.TerminalSize

	// Guard writes to the WS from multiple goroutines.
	writeMu sync.Mutex

	// Pending stdin buffer not yet consumed by Read().
	pending []byte

	once sync.Once
	done chan struct{}

	lastInput time.Time
	lastMu    sync.Mutex
}

func newExecBridge(conn *websocket.Conn, cancel context.CancelFunc) *execBridge {
	b := &execBridge{
		conn:      conn,
		cancel:    cancel,
		stdinCh:   make(chan []byte, 32),
		sizeCh:    make(chan *remotecommand.TerminalSize, 4),
		done:      make(chan struct{}),
		lastInput: time.Now(),
	}
	go b.readLoop()
	go b.idleWatchdog()
	return b
}

func (b *execBridge) markInput() {
	b.lastMu.Lock()
	b.lastInput = time.Now()
	b.lastMu.Unlock()
}

func (b *execBridge) idleWatchdog() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-t.C:
			b.lastMu.Lock()
			idle := time.Since(b.lastInput)
			b.lastMu.Unlock()
			if idle > execIdleTimeout {
				_ = b.conn.WriteMessage(websocket.TextMessage,
					[]byte(`{"type":"error","message":"session idle timeout"}`))
				b.cancel()
				return
			}
		}
	}
}

func (b *execBridge) readLoop() {
	defer func() {
		close(b.stdinCh)
		b.cancel()
	}()
	for {
		msgType, data, err := b.conn.ReadMessage()
		if err != nil {
			return
		}
		switch msgType {
		case websocket.BinaryMessage:
			b.markInput()
			select {
			case b.stdinCh <- data:
			case <-b.done:
				return
			}
		case websocket.TextMessage:
			var ctrl execControl
			if err := json.Unmarshal(data, &ctrl); err == nil && ctrl.Type == "resize" {
				select {
				case b.sizeCh <- &remotecommand.TerminalSize{Width: ctrl.Cols, Height: ctrl.Rows}:
				default:
				}
				continue
			}
			// Treat loose text as stdin for convenience.
			b.markInput()
			select {
			case b.stdinCh <- data:
			case <-b.done:
				return
			}
		}
	}
}

// Read implements io.Reader (stdin for the exec stream).
func (b *execBridge) Read(p []byte) (int, error) {
	if len(b.pending) > 0 {
		n := copy(p, b.pending)
		b.pending = b.pending[n:]
		return n, nil
	}
	data, ok := <-b.stdinCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, data)
	if n < len(data) {
		b.pending = data[n:]
	}
	return n, nil
}

// Write implements io.Writer (stdout/stderr merged; sent as binary WS frames).
func (b *execBridge) Write(p []byte) (int, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := b.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Next implements remotecommand.TerminalSizeQueue.
func (b *execBridge) Next() *remotecommand.TerminalSize {
	select {
	case sz := <-b.sizeCh:
		return sz
	case <-b.done:
		return nil
	}
}

func (b *execBridge) Close() error {
	b.once.Do(func() { close(b.done) })
	return nil
}
