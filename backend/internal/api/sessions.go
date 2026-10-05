package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/models"
)

// Admin-only endpoints for session management. Non-admin users don't currently
// have a per-user "my sessions" view — the UI shows it under Admin for now,
// which matches how other security knobs (users, roles, audit) live.

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userIDParam := r.URL.Query().Get("userId")
	activeOnly := r.URL.Query().Get("activeOnly") == "1" || r.URL.Query().Get("activeOnly") == "true"
	userID := 0
	if userIDParam != "" {
		id, err := strconv.Atoi(userIDParam)
		if err == nil {
			userID = id
		}
	}
	rows, err := s.store.ListSessions(r.Context(), userID, activeOnly)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	if rows == nil {
		rows = []models.SessionTokenRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Fetch the row first so we can drop the throttle entry (keyed by jti) and
	// write an audit line that names the user, not just the row id.
	rows, lerr := s.store.ListSessions(r.Context(), 0, false)
	var targetJTI, targetUser string
	if lerr == nil {
		for _, row := range rows {
			if row.ID == id {
				targetJTI = row.JTI
				targetUser = row.Username
				break
			}
		}
	}
	if err := s.store.RevokeSession(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke")
		return
	}
	if targetJTI != "" {
		s.sessionToucher.Forget(targetJTI)
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         userName(user),
		Action:       "session.revoke",
		Namespace:    "-",
		ResourceType: "session",
		ResourceName: targetUser,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleRevokeAllForUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.RevokeAllForUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke")
		return
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         userName(user),
		Action:       "session.revoke_all",
		Namespace:    "-",
		ResourceType: "session",
		ResourceName: "user:" + strconv.Itoa(id),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
