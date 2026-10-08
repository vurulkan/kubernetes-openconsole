package recording

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// Truncation reasons surfaced in Result and the session-end audit entry.
const (
	ReasonSizeLimit  = "size_limit"
	ReasonDiskQuota  = "disk_quota"
	ReasonWriteError = "write_error"
)

const (
	defaultCols   = 80
	defaultRows   = 24
	flushInterval = time.Second
)

// Meta describes the exec session being recorded.
type Meta struct {
	User      string
	Cluster   string
	Namespace string
	Pod       string
	Container string
	RequestID string
	// Initial terminal size if the client sent one; 0 → wait for the first
	// resize (or fall back to 80x24 when output arrives first).
	Cols, Rows uint16
}

// Result is returned by Close for the session-end audit entry.
type Result struct {
	SessionID      string
	SizeBytes      int64
	Duration       time.Duration
	Truncated      bool
	TruncateReason string
}

// Session streams one exec session to an asciicast v2 file. All methods are
// safe for concurrent use and safe on a nil receiver, so the exec bridge can
// call them unconditionally when recording is disabled.
type Session struct {
	m         *Manager
	rowID     int
	sessionID string
	path      string
	meta      Meta
	start     time.Time
	maxBytes  int64

	mu         sync.Mutex
	f          *os.File
	w          *bufio.Writer
	headerDone bool
	cols, rows uint16
	carry      []byte // incomplete trailing UTF-8 sequence from the last chunk
	size       int64
	stopped    bool
	truncated  bool
	reason     string
	lastFlush  time.Time
	closed     bool
	result     Result
}

// ID returns the session UUID (also the .cast file basename).
func (s *Session) ID() string {
	if s == nil {
		return ""
	}
	return s.sessionID
}

// Write records a chunk of terminal output. It never fails the caller: a
// write error stops recording for this session but the shell keeps running.
func (s *Session) Write(p []byte) {
	if s == nil || len(p) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.closed {
		return
	}
	data := p
	if len(s.carry) > 0 {
		data = append(s.carry, p...)
		s.carry = nil
	}
	// SPDY chunks can split a multi-byte rune; hold the tail back so the
	// player doesn't render two replacement chars for one Turkish letter.
	data, rest := splitIncompleteUTF8(data)
	if len(rest) > 0 {
		s.carry = append([]byte(nil), rest...)
	}
	if len(data) > 0 {
		s.emit("o", string(data))
	}
}

// Resize records a terminal size change. Before the header is written it
// just sets the header dimensions.
func (s *Session) Resize(cols, rows uint16) {
	if s == nil || cols == 0 || rows == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.closed {
		return
	}
	if !s.headerDone {
		s.cols, s.rows = cols, rows
		return
	}
	if cols == s.cols && rows == s.rows {
		return
	}
	s.cols, s.rows = cols, rows
	s.emit("r", strconv.Itoa(int(cols))+"x"+strconv.Itoa(int(rows)))
}

// Stop ends recording early (disk guard). The exec session keeps running.
func (s *Session) Stop(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.closed {
		return
	}
	s.truncate(reason)
}

// Size returns the bytes written so far.
func (s *Session) Size() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Close flushes the file, finalizes the DB row and returns the summary.
// Calling it more than once returns the same result.
func (s *Session) Close() Result {
	if s == nil {
		return Result{}
	}
	s.mu.Lock()
	if s.closed {
		res := s.result
		s.mu.Unlock()
		return res
	}
	if !s.stopped && len(s.carry) > 0 {
		s.emit("o", string(s.carry))
		s.carry = nil
	}
	if !s.headerDone {
		// Keep zero-output sessions playable: a header alone is valid v2.
		s.writeHeader()
	}
	if err := s.w.Flush(); err != nil {
		slog.Warn("recording flush failed", slog.String("session_id", s.sessionID), slog.Any("error", err))
	}
	if err := s.f.Close(); err != nil {
		slog.Warn("recording close failed", slog.String("session_id", s.sessionID), slog.Any("error", err))
	}
	s.closed = true
	s.result = Result{
		SessionID:      s.sessionID,
		SizeBytes:      s.size,
		Duration:       time.Since(s.start),
		Truncated:      s.truncated,
		TruncateReason: s.reason,
	}
	res := s.result
	s.mu.Unlock()

	s.m.finish(s, res)
	return res
}

// emit writes one event line. Caller holds s.mu.
func (s *Session) emit(kind, data string) {
	if !s.headerDone {
		s.writeHeader()
	}
	line := encodeEvent(time.Since(s.start).Seconds(), kind, data)
	if s.maxBytes > 0 && s.size+int64(len(line)) > s.maxBytes {
		s.truncate(ReasonSizeLimit)
		return
	}
	s.writeRaw(line)
	if !s.stopped && time.Since(s.lastFlush) >= flushInterval {
		if err := s.w.Flush(); err != nil {
			s.fail(err)
		}
		s.lastFlush = time.Now()
	}
}

// truncate appends a visible marker and stops further writes. The marker may
// exceed the cap by a few dozen bytes. Caller holds s.mu.
func (s *Session) truncate(reason string) {
	if !s.headerDone {
		s.writeHeader()
	}
	msg := "\r\n\x1b[33m[openconsole: recording stopped (" + reason + ")]\x1b[0m\r\n"
	s.writeRaw(encodeEvent(time.Since(s.start).Seconds(), "o", msg))
	_ = s.w.Flush()
	s.stopped = true
	s.truncated = true
	if s.reason == "" {
		s.reason = reason
	}
	slog.Warn("recording truncated",
		slog.String("session_id", s.sessionID),
		slog.String("reason", reason),
		slog.Int64("size_bytes", s.size),
		slog.String("request_id", s.meta.RequestID),
	)
}

func (s *Session) writeHeader() {
	cols, rows := s.cols, s.rows
	if cols == 0 || rows == 0 {
		cols, rows = defaultCols, defaultRows
		s.cols, s.rows = cols, rows
	}
	title := s.meta.User + " → " + s.meta.Namespace + "/" + s.meta.Pod
	if s.meta.Container != "" {
		title += "/" + s.meta.Container
	}
	header := struct {
		Version   int               `json:"version"`
		Width     uint16            `json:"width"`
		Height    uint16            `json:"height"`
		Timestamp int64             `json:"timestamp"`
		Title     string            `json:"title"`
		Env       map[string]string `json:"env"`
	}{2, cols, rows, s.start.Unix(), title, map[string]string{"TERM": "xterm-256color"}}
	b, _ := json.Marshal(header)
	s.headerDone = true
	s.writeRaw(append(b, '\n'))
}

func (s *Session) writeRaw(line []byte) {
	if s.stopped {
		return
	}
	n, err := s.w.Write(line)
	s.size += int64(n)
	if err != nil {
		s.fail(err)
	}
}

func (s *Session) fail(err error) {
	slog.Warn("recording write failed",
		slog.String("session_id", s.sessionID),
		slog.Any("error", err),
		slog.String("request_id", s.meta.RequestID),
	)
	s.stopped = true
	s.truncated = true
	if s.reason == "" {
		s.reason = ReasonWriteError
	}
}

// encodeEvent renders `[time, "kind", "data"]\n`. Invalid UTF-8 is replaced
// with U+FFFD by encoding/json; HTML escaping is off to keep files small.
func encodeEvent(t float64, kind, data string) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data) + 32)
	buf.WriteByte('[')
	buf.WriteString(strconv.FormatFloat(t, 'f', 6, 64))
	buf.WriteString(`,"` + kind + `",`)
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(data)
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return append(out, ']', '\n')
}

// splitIncompleteUTF8 splits b into a prefix that ends on a rune boundary and
// a trailing partial rune (at most 3 bytes) to carry into the next chunk.
func splitIncompleteUTF8(b []byte) ([]byte, []byte) {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if utf8.FullRune(b[i:]) {
				return b, nil
			}
			return b[:i], b[i:]
		}
	}
	return b, nil
}
