package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

// Request body limits: maxBody for every request, more for a YAML apply (an
// object may be up to etcd's 1.5 MiB, JSON-escaped) and the logo upload.
const (
	maxBody      = 1 << 20
	maxApplyBody = 4 << 20
)

// limitBody answers 413 to a request that declares a body over its limit and
// caps the rest, so no handler (sign-in included, before any login) reads an
// unbounded body; a capped read fails the handler's decode.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxBody)
		switch {
		case strings.HasSuffix(r.URL.Path, "/apply"):
			limit = maxApplyBody
		case r.URL.Path == "/api/admin/customization/logo":
			limit = maxLogoSize + maxBody
		}
		if r.ContentLength > limit {
			writeError(w, http.StatusRequestEntityTooLarge, problem.BodyTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacker not supported")
	}
	conn, rw, err := hijacker.Hijack()
	if err == nil {
		// The WebSocket upgrade writes its 101 on the raw connection.
		r.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := r.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), logpkg.RequestIDKey, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func logWarnf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func newRequestID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// quietPaths are logged at debug level when they succeed.
var quietPaths = map[string]bool{"/healthz": true, "/livez": true, "/readyz": true, "/metrics": true}

// requestKey carries the API key a request was made with out to requestLogger,
// which wraps the router and so never sees the context the auth middleware builds.
type requestKey struct {
	id   int
	name string
}

type requestKeyCtx struct{}

// noteRequestKey records the request's API key for its http.request line.
func noteRequestKey(ctx context.Context, k *models.APIKey) {
	if h, ok := ctx.Value(requestKeyCtx{}).(*requestKey); ok && k != nil {
		h.id, h.name = k.ID, k.Name
	}
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		key := &requestKey{}
		r = r.WithContext(context.WithValue(r.Context(), requestKeyCtx{}, key))
		start := time.Now()
		next.ServeHTTP(recorder, r)
		duration := time.Since(start)

		level := slog.LevelInfo
		if recorder.status >= 500 {
			level = slog.LevelError
		} else if recorder.status >= 400 {
			level = slog.LevelWarn
		} else if quietPaths[r.URL.Path] {
			// Kubelet probes and Prometheus scrapes arrive every few seconds;
			// successful ones are only logged at debug level.
			level = slog.LevelDebug
		}

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int64("duration_ms", duration.Milliseconds()),
			slog.String("remote_ip", clientIP(r)),
			slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
			slog.String("user_agent", r.UserAgent()),
		}
		if key.id != 0 {
			// ECS: openconsole.api_key.id / .name, as on audit events.
			attrs = append(attrs, slog.Int("api_key_id", key.id), slog.String("api_key_name", key.name))
		}
		if logpkg.ECS() {
			// ECS event.duration is in nanoseconds; milliseconds would turn
			// every fast request into 0.
			attrs[3] = slog.Int64("duration_ns", duration.Nanoseconds())
			attrs = append(attrs, slog.Int64("response_bytes", recorder.bytes))
		}
		// Name the request's span after the route pattern (low cardinality)
		// and link the log line to the trace.
		if span := trace.SpanFromContext(r.Context()); span.SpanContext().IsValid() {
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				span.SetName(r.Method + " " + rc.RoutePattern())
			}
			span.SetAttributes(attribute.String("openconsole.request_id", logpkg.RequestIDFrom(r.Context())))
			attrs = append(attrs, slog.String("trace_id", span.SpanContext().TraceID().String()))
		}
		slog.LogAttrs(r.Context(), level, "http.request", attrs...)
		metricsRecordRequest(recorder.status, duration.Milliseconds())
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.ErrorContext(r.Context(), "http.panic",
					slog.Any("error", err),
					slog.String("path", r.URL.Path),
					slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
				)
				writeError(w, http.StatusInternalServerError, problem.InternalError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.staticDir, filepath.Clean(r.URL.Path))
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		http.ServeFile(w, r, path)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
}
