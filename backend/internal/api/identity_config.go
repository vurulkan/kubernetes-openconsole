package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

func (s *Server) handleGetLDAP(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	cfg.BindPassword = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleGetAzureAD(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	cfg.ClientSecret = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleUpdateLDAP(w http.ResponseWriter, r *http.Request) {
	noteFor(r).Name = "ldap"
	var request models.LDAPConfig
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	request.CACert = strings.TrimSpace(request.CACert)
	if request.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(request.CACert)) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "ldap CA certificate: no PEM certificate found")
		return
	}
	if err := s.store.UpdateLDAPConfig(r.Context(), request); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleUpdateAzureAD(w http.ResponseWriter, r *http.Request) {
	noteFor(r).Name = "azure_ad"
	var request models.AzureADConfig
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	if err := s.store.UpdateAzureADConfig(r.Context(), request); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleTestLDAP(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load ldap config")
		return
	}
	if err := auth.TestConnection(ldapAuthConfig(cfg)); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.ConnectionFailed, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleTestAzureAD(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load azure ad config")
		return
	}
	if cfg.TenantID == "" || cfg.ClientID == "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "tenant and client id are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := auth.TestAzureConnection(ctx, auth.AzureADConfig{
		Authority:    s.azureAuthority,
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.ConnectionFailed, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSearchLDAPUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load ldap config")
		return
	}
	users, err := auth.SearchUsers(ldapAuthConfig(cfg), request.Query)
	if err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.ConnectionFailed, err.Error())
		return
	}
	type result struct {
		auth.LDAPUser
		// Exists: an OpenConsole account with this name is already there.
		Exists bool `json:"exists"`
	}
	items := make([]result, 0, len(users))
	for _, u := range users {
		_, err := s.store.GetUserByUsername(r.Context(), u.Username)
		items = append(items, result{LDAPUser: u, Exists: err == nil})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleImportLDAPUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Usernames []string `json:"usernames"`
		// Optional groups every newly imported user is added to, so they
		// can see something on their first sign-in.
		GroupIDs []int `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	var created, skipped, failed []string
	for _, username := range request.Usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		if _, err := s.store.GetUserByUsername(r.Context(), username); err == nil {
			skipped = append(skipped, username)
			continue
		}
		randomHash, err := auth.HashPassword(randomPassword())
		if err == nil {
			_, err = s.store.CreateDirectoryUser(r.Context(), username, randomHash, models.AuthSourceLDAP, request.GroupIDs)
		}
		if err != nil {
			slog.Warn("LDAP import failed", slog.String("user", username), slog.Any("error", err))
			failed = append(failed, username)
			continue
		}
		created = append(created, username)
	}
	summary := strings.Join(created, ", ")
	if r := []rune(summary); len(r) > 500 {
		summary = string(r[:500]) + "…"
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbImport, ResourceType: audit.KindUser, ResourceName: "*",
		Details: audit.D{"account_source": models.AuthSourceLDAP, "count": len(created), "groups": len(request.GroupIDs), "summary": summary}})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"created":         len(created),
		"createdUsers":    created,
		"skippedExisting": skipped,
		"failed":          failed,
	})
}

func randomPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "temporary-password"
	}
	return fmt.Sprintf("%x", b)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSession(w http.ResponseWriter, r *http.Request) {
	noteFor(r).Name = "session"
	// Fields left out of the body keep their value.
	request, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	if request.SessionMinutes <= 0 {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "sessionMinutes must be a positive number")
		return
	}
	if request.APIKeyMaxDays < 0 || request.APIKeyMaxDays > 3650 {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "the longest API key lifetime is 0 (no limit) to 3650 days")
		return
	}
	if err := s.store.UpdateSessionSettings(r.Context(), request); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	noteFor(r).Details = audit.D{"summary": fmt.Sprintf("session_minutes=%d api_key_max_days=%d api_key_allow_no_expiry=%t",
		request.SessionMinutes, request.APIKeyMaxDays, request.APIKeyAllowNoExpiry)}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
