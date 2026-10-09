package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/recording"
)

// Default shells tried in order when the client did not pick one.
var defaultShells = []string{"/bin/bash", "/bin/sh", "/bin/ash"}

// Exec limits, set from EXEC_IDLE_TIMEOUT / MAX_EXEC_SESSIONS_PER_USER at
// startup (SetExecLimits).
var (
	// execIdleTimeout closes a session after this long without stdin.
	execIdleTimeout = 5 * time.Minute
	// maxExecSessionsPerUser caps concurrent shells per user; 0 = no cap.
	maxExecSessionsPerUser = 3
)

// SetExecLimits applies the configured exec limits.
func SetExecLimits(idle time.Duration, maxPerUser int) {
	if idle > 0 {
		execIdleTimeout = idle
	}
	if maxPerUser >= 0 {
		maxExecSessionsPerUser = maxPerUser
	}
}

// execSessionTracker counts open shells per user.
type execSessionTracker struct {
	mu     sync.Mutex
	byUser map[int]int
}

// acquire reserves a slot; false when the user is at the limit.
func (t *execSessionTracker) acquire(userID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byUser == nil {
		t.byUser = map[int]int{}
	}
	if maxExecSessionsPerUser > 0 && t.byUser[userID] >= maxExecSessionsPerUser {
		return false
	}
	t.byUser[userID]++
	metricExecActive.Add(1)
	return true
}

func (t *execSessionTracker) release(userID int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byUser[userID] > 0 {
		t.byUser[userID]--
		metricExecActive.Add(-1)
	}
	if t.byUser[userID] == 0 {
		delete(t.byUser, userID)
	}
}

// closeTooManySessions is the WebSocket close code (application range) sent
// when the per-user shell limit is reached.
const closeTooManySessions = 4429

// execWriteTimeout bounds a single WebSocket write so a stalled browser can't
// hold the write lock (and with it the idle watchdog) forever.
const execWriteTimeout = 15 * time.Second

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
		s.recordExecAudit(claims.Username, namespace, pod, "denied", "", r)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Concurrent-shell cap. Browsers hide the status of a failed WebSocket
	// handshake from scripts, so a browser gets the socket, a readable error
	// frame and close code 4429; any other client gets a plain 429.
	if !s.execSessions.acquire(claims.UserID) {
		s.recordExecAudit(claims.Username, namespace, pod, "rate_limited",
			"max_sessions="+strconv.Itoa(maxExecSessionsPerUser), r)
		msg := "too many open shells (limit " + strconv.Itoa(maxExecSessionsPerUser) + " per user); close one first"
		if websocket.IsWebSocketUpgrade(r) {
			upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
			if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
				writeExecSessionInfo(conn)
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"too_many_sessions","limit":`+
					strconv.Itoa(maxExecSessionsPerUser)+`,"message":`+jsonString(msg)+`}`))
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(closeTooManySessions, "too many open shells"),
					time.Now().Add(time.Second))
				_ = conn.Close()
			}
			return
		}
		writeError(w, http.StatusTooManyRequests, msg)
		return
	}
	defer s.execSessions.release(claims.UserID)

	container := strings.TrimSpace(r.URL.Query().Get("container"))
	command := strings.TrimSpace(r.URL.Query().Get("command"))
	if command == "" {
		command = "auto"
	}

	client, ok := kubeFor(r).Client()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	cfg, ok := kubeFor(r).RESTConfig()
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
	writeExecSessionInfo(conn)

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
		s.recordExecAudit(claims.Username, namespace, pod, "failed", "spdy_init:"+err.Error(), r)
		return
	}

	// Recording is fail-open: if it can't start, the shell still opens and
	// the reason lands in the audit log. The client only shows the
	// "being recorded" banner when it receives the recording frame.
	rec := s.startExecRecording(r, conn, claims.Username, namespace, pod, container, requestID)
	defer rec.Close()

	start := time.Now()
	s.recordExecAudit(claims.Username, namespace, pod, "start",
		"container="+container+";cmd="+command, r)
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

	bridge := newExecBridge(conn, cancel, rec)
	defer bridge.Close()

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             bridge,
		Stdout:            bridge,
		Stderr:            bridge,
		Tty:               true,
		TerminalSizeQueue: bridge,
	})

	// A shell that exits with a non-zero code (`exit 3`, last command
	// failed) is a normal end, not a failure: record the code. Exit code -1
	// = the session was cut (browser closed, idle timeout).
	outcome := "end"
	exitCode := -1
	errDetail := ""
	var exitErr utilexec.ExitError
	switch {
	case err == nil:
		exitCode = 0
	case errors.As(err, &exitErr):
		exitCode = exitErr.ExitStatus()
	case errors.Is(err, context.Canceled), errors.Is(err, io.EOF):
	default:
		outcome = "failed"
		errDetail = err.Error() + ";"
		bridge.writeError("exec ended: " + err.Error())
	}
	duration := time.Since(start)
	bytesIn, bytesOut := bridge.bytesIn.Load(), bridge.bytesOut.Load()
	s.recordExecAudit(claims.Username, namespace, pod, outcome,
		errDetail+"container="+container+
			";exit="+strconv.Itoa(exitCode)+
			";bytes_in="+strconv.FormatInt(bytesIn, 10)+
			";bytes_out="+strconv.FormatInt(bytesOut, 10)+
			";dur_ms="+itoa(duration.Milliseconds()), r)
	slog.Info("pod.exec.end",
		slog.String("user", claims.Username),
		slog.String("namespace", namespace),
		slog.String("pod", pod),
		slog.String("outcome", outcome),
		slog.Int("exit_code", exitCode),
		slog.Int64("bytes_in", bytesIn),
		slog.Int64("bytes_out", bytesOut),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.String("request_id", requestID),
	)

	if rec != nil {
		res := rec.Close()
		detail := "session_id=" + res.SessionID +
			";size=" + strconv.FormatInt(res.SizeBytes, 10) +
			";dur_ms=" + itoa(res.Duration.Milliseconds())
		if res.Truncated {
			detail += ";truncated=" + res.TruncateReason
		}
		s.recordExecAudit(claims.Username, namespace, pod, "session.recorded", detail, r)
	}
}

// startExecRecording opens a recording for the session and tells the client
// about it. Returns nil (which the bridge treats as "not recording") when
// recording is off, refused by the disk guard, or failed to start.
func (s *Server) startExecRecording(r *http.Request, conn *websocket.Conn, user, namespace, pod, container, requestID string) *recording.Session {
	if s.recorder == nil {
		return nil
	}
	cluster := clusterFrom(r.Context()).Name
	cols, _ := strconv.ParseUint(r.URL.Query().Get("cols"), 10, 16)
	rows, _ := strconv.ParseUint(r.URL.Query().Get("rows"), 10, 16)
	rec, err := s.recorder.Start(r.Context(), recording.Meta{
		User:      user,
		Cluster:   cluster,
		Namespace: namespace,
		Pod:       pod,
		Container: container,
		RequestID: requestID,
		Cols:      uint16(cols),
		Rows:      uint16(rows),
	})
	switch {
	case err == nil:
		// Sent before the bridge starts, so no concurrent writer yet.
		_ = conn.WriteMessage(websocket.TextMessage,
			[]byte(`{"type":"recording","enabled":true,"sessionId":`+jsonString(rec.ID())+`}`))
		return rec
	case errors.Is(err, recording.ErrDisabled):
	case errors.Is(err, recording.ErrNoSpace):
		s.recordExecAudit(user, namespace, pod, "session.record_skipped", "reason=disk_quota", r)
	default:
		slog.Warn("exec recording failed to start",
			slog.Any("error", err),
			slog.String("request_id", requestID),
		)
		s.recordExecAudit(user, namespace, pod, "session.record_failed", err.Error(), r)
	}
	return nil
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

// writeExecSessionInfo tells the client the configured idle timeout so its
// banner shows the real value.
func writeExecSessionInfo(conn *websocket.Conn) {
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"session","idleTimeoutSeconds":`+
		strconv.Itoa(int(execIdleTimeout/time.Second))+`}`))
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
func (s *Server) recordExecAudit(user, namespace, pod, outcome, detail string, r *http.Request) {
	resource := pod
	if detail != "" {
		resource = pod + " (" + detail + ")"
	}
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         user,
		Action:       "pod.exec." + outcome,
		Namespace:    namespace,
		ResourceType: "pod",
		ResourceName: resource,
	})
}

// execBridge wires a WebSocket conn to the io.Reader / io.Writer /
// remotecommand.TerminalSizeQueue expected by remotecommand.StreamOptions.
// It also enforces the exec idle timeout and surfaces resize messages.
type execBridge struct {
	conn   *websocket.Conn
	cancel context.CancelFunc

	// rec receives a copy of stdout/stderr and resize events; nil-safe.
	rec *recording.Session

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

	// Traffic counters for the session-end audit entry.
	bytesIn  atomic.Int64 // stdin from the browser
	bytesOut atomic.Int64 // stdout/stderr from the pod
}

func newExecBridge(conn *websocket.Conn, cancel context.CancelFunc, rec *recording.Session) *execBridge {
	b := &execBridge{
		conn:      conn,
		cancel:    cancel,
		rec:       rec,
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
	tick := 30 * time.Second
	if execIdleTimeout < 2*tick {
		tick = execIdleTimeout / 2
	}
	t := time.NewTicker(tick)
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
				b.writeError("session idle timeout")
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
			b.bytesIn.Add(int64(len(data)))
			select {
			case b.stdinCh <- data:
			case <-b.done:
				return
			}
		case websocket.TextMessage:
			var ctrl execControl
			if err := json.Unmarshal(data, &ctrl); err == nil && ctrl.Type == "resize" {
				b.rec.Resize(ctrl.Cols, ctrl.Rows)
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
	// Record what the pod emitted even if the browser has gone away.
	b.rec.Write(p)
	b.bytesOut.Add(int64(len(p)))
	if err := b.writeFrame(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeError sends a {"type":"error"} control frame to the client.
func (b *execBridge) writeError(msg string) {
	_ = b.writeFrame(websocket.TextMessage, []byte(`{"type":"error","message":`+jsonString(msg)+`}`))
}

// writeFrame is the only way the bridge writes to the WebSocket. gorilla
// allows a single concurrent writer and panics on overlap — in a goroutine
// that panic takes the whole server down — so stdout, the idle watchdog and
// the end-of-session error all serialize on writeMu.
func (b *execBridge) writeFrame(msgType int, data []byte) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	_ = b.conn.SetWriteDeadline(time.Now().Add(execWriteTimeout))
	return b.conn.WriteMessage(msgType, data)
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
