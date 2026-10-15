package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

// handleResetUserPassword lets an admin set a new password for a LOCAL user
// (POST /api/admin/users/{id}/reset-password {"password", "mustChange"}).
// LDAP and Azure AD users are refused: their password lives in the
// directory, and a local one would let them sign in around it. By default the
// user must change the password at next login, and every existing session of
// that user is revoked. Audited as user.reset_password (success, denied, failed).
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
		s.recordPasswordResetAudit(r, "id:"+strconv.Itoa(id), audit.Denied, reasonAdminOnly, nil)
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.AuthSource != models.AuthSourceLocal {
		s.recordPasswordResetAudit(r, target.Username, audit.Failed, "not_local_account", audit.D{"account_source": target.AuthSource})
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
		s.recordPasswordResetAudit(r, target.Username, audit.Failed, "error", failDetails(err, nil))
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	// The old password may be known to someone else: sign the user out
	// everywhere.
	if err := s.store.RevokeAllForUser(r.Context(), target.ID); err != nil {
		slog.Warn("revoke sessions after password reset failed", slog.String("user", target.Username), slog.Any("error", err))
	}
	s.recordPasswordResetAudit(r, target.Username, audit.Success, "", audit.D{"must_change": mustChange})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "mustChangePassword": mustChange})
}

func (s *Server) recordPasswordResetAudit(r *http.Request, target, outcome, reason string, details audit.D) {
	s.auditEvent(r, models.AuditLog{
		Verb:         audit.VerbResetPassword,
		Outcome:      outcome,
		Reason:       reason,
		ResourceType: audit.KindUser,
		ResourceName: target,
		Details:      details,
	})
}
