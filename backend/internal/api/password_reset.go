package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

// handleResetUserPassword lets an admin set a new password for a LOCAL user
// (POST /api/admin/users/{id}/reset-password {"password", "mustChange"}).
// LDAP and Azure AD users are refused: their password lives in the
// directory, and a local one would let them sign in around it. By default the
// user must change the password at next login, and every existing session of
// that user is revoked. Audited as user.password_reset.{success,denied,failed}.
func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if !admin.IsAdmin || admin.MustChangePassword {
		s.recordPasswordResetAudit(r, admin.Username, "id:"+strconv.Itoa(id), "denied", "")
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.AuthSource != models.AuthSourceLocal {
		s.recordPasswordResetAudit(r, admin.Username, target.Username, "failed", "source="+target.AuthSource)
		writeError(w, http.StatusConflict, "this user signs in through "+target.AuthSource+"; reset the password there")
		return
	}
	body := struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"mustChange"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := auth.CheckPasswordPolicy(body.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mustChange := body.MustChange == nil || *body.MustChange
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), target.ID, hash, mustChange); err != nil {
		s.recordPasswordResetAudit(r, admin.Username, target.Username, "failed", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	// The old password may be known to someone else: sign the user out
	// everywhere.
	if err := s.store.RevokeAllForUser(r.Context(), target.ID); err != nil {
		slog.Warn("revoke sessions after password reset failed", slog.String("user", target.Username), slog.Any("error", err))
	}
	s.recordPasswordResetAudit(r, admin.Username, target.Username, "success", "must_change="+strconv.FormatBool(mustChange))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "mustChangePassword": mustChange})
}

func (s *Server) recordPasswordResetAudit(r *http.Request, admin, target, outcome, detail string) {
	name := target
	if detail != "" {
		name += " (" + detail + ")"
	}
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         admin,
		Action:       "user.password_reset." + outcome,
		Namespace:    "-",
		ResourceType: "user",
		ResourceName: name,
		Cluster:      "-",
	})
	slog.Info("user.password_reset",
		slog.String("outcome", outcome),
		slog.String("admin", admin),
		slog.String("user", target),
		slog.String("details", detail),
		slog.String("request_id", requestIDOf(r)),
	)
}
