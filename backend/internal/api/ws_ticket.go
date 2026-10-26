package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s-dashboard/backend/internal/auth"
)

// handleWSTicket trades the caller's bearer token for a single-use ticket the
// browser puts in a WebSocket URL (?ticket=). The socket's own handler checks
// permissions and audits; the ticket only proves who is calling.
func (s *Server) handleWSTicket(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !strings.HasPrefix(body.Path, "/ws/") {
		writeError(w, http.StatusBadRequest, "path must be a /ws/ endpoint")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ticket": auth.IssueTicket(claims, body.Path)})
}
