package api

import (
	"log/slog"
	"net/http"
	"time"
)

// extendWriteDeadline lifts the server's WriteTimeout (60 s) for one
// response that may legitimately take longer: a command with a long
// timeout, a large export, a download. Without it the server cuts the
// connection and the client gets an empty answer, although the action ran
// (and an agent may run it again).
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d)); err != nil {
		slog.Warn("could not extend the write deadline", slog.Any("error", err))
	}
}

// Unwrap lets http.ResponseController reach the server's writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
