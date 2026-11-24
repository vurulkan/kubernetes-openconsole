package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

// Azure AD directory search (M31): with Admin → Azure AD → Directory search on,
// New user → Azure AD searches Entra ID through Microsoft Graph and creates
// the picked people as Azure AD accounts bound to their object id (oid).

// importResult is one person of a directory import (LDAP or Azure AD).
type importResult struct {
	ID       string `json:"id,omitempty"` // Entra object id (Azure AD)
	Username string `json:"username"`
	Status   string `json:"status"`           // created | skipped | failed
	Reason   string `json:"reason,omitempty"` // skipped: exists; failed: a reason code
}

// graphClient is the Graph client of the saved app registration.
func (s *Server) graphClient(cfg models.AzureADConfig) *auth.GraphClient {
	root := s.graphURL
	if root == "" {
		root = auth.GraphRoot(s.azureAuthority)
	}
	return &auth.GraphClient{GraphRoot: root, Cfg: auth.AzureADConfig{
		Authority: s.azureAuthority, TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
	}}
}

// writeGraphError answers a Graph failure with its reason code (502: the
// upstream refused or failed) and logs it for the operator.
func writeGraphError(w http.ResponseWriter, r *http.Request, err error) {
	ge := auth.AsGraphError(err)
	if ge == nil {
		ge = &auth.GraphError{Code: problem.GraphUnreachable, Detail: err.Error()}
	}
	slog.Warn("microsoft graph request failed", slog.String("error", ge.Code), slog.String("detail", ge.Detail),
		slog.String("path", r.URL.Path))
	switch ge.Code {
	case problem.GraphForbidden:
		writeErrorDetail(w, http.StatusBadGateway, problem.GraphForbidden, ge.Detail)
	case problem.GraphInvalidClient:
		writeErrorDetail(w, http.StatusBadGateway, problem.GraphInvalidClient, ge.Detail)
	default:
		writeErrorDetail(w, http.StatusBadGateway, problem.GraphUnreachable, ge.Detail)
	}
}

// azureGraphConfig loads the Azure AD settings; ok=false has answered.
func (s *Server) azureGraphConfig(w http.ResponseWriter, r *http.Request, needSearch bool) (models.AzureADConfig, bool) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load azure ad config")
		return cfg, false
	}
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.NotConfigured, "tenant id, client id and client secret are required")
		return cfg, false
	}
	if needSearch && (!cfg.Enabled || !cfg.GraphSearch) {
		writeErrorDetail(w, http.StatusBadRequest, problem.NotConfigured, "azure ad directory search is off")
		return cfg, false
	}
	return cfg, true
}

func (s *Server) handleTestAzureGraph(w http.ResponseWriter, r *http.Request) {
	cfg, ok := s.azureGraphConfig(w, r, false)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.graphClient(cfg).Test(ctx); err != nil {
		writeGraphError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSearchAzureUsers is not audited (like the LDAP search); creating the
// accounts is.
func (s *Server) handleSearchAzureUsers(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	cfg, ok := s.azureGraphConfig(w, r, true)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	users, err := s.graphClient(cfg).SearchUsers(ctx, body.Query)
	if err != nil {
		writeGraphError(w, r, err)
		return
	}
	type item struct {
		auth.GraphUser
		// Exists: an account has this name or is bound to this person already.
		Exists bool `json:"exists"`
	}
	items := make([]item, 0, len(users))
	for _, u := range users {
		exists, err := s.store.DirectoryAccountExists(r.Context(), u.Username, u.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
		items = append(items, item{GraphUser: u, Exists: exists})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleImportAzureUsers creates the picked people (by Entra object id) as Azure
// AD accounts, bound to that id, optionally in groups. Each person is read
// from Graph again: the name comes from the directory, not from the client.
func (s *Server) handleImportAzureUsers(w http.ResponseWriter, r *http.Request) {
	note := noteFor(r)
	note.Name = "*"
	var body struct {
		IDs      []string `json:"ids"`
		GroupIDs []int    `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	cfg, ok := s.azureGraphConfig(w, r, true)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	g := s.graphClient(cfg)
	results := make([]importResult, 0, len(body.IDs))
	var created []string
	for _, id := range body.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		res := importResult{ID: id, Username: id, Status: "failed"}
		u, err := g.User(ctx, id)
		switch {
		case err != nil:
			res.Reason = problem.GraphUnreachable
			if ge := auth.AsGraphError(err); ge != nil {
				res.Reason = ge.Code
			}
		case u.Username == "":
			res.Reason = problem.InvalidInput // a guest without an e-mail address
		default:
			res.Username = u.Username
			res.Reason = s.createAzureAccount(r.Context(), u, body.GroupIDs)
			if res.Reason == "" {
				res.Status = "created"
				created = append(created, u.Username)
			} else if res.Reason == "exists" {
				res.Status = "skipped"
			}
		}
		results = append(results, res)
	}
	summary := strings.Join(created, ", ")
	if r := []rune(summary); len(r) > 500 {
		summary = string(r[:500]) + "…"
	}
	note.Details = audit.D{"account_source": models.AuthSourceAzure, "count": len(created), "groups": len(body.GroupIDs), "summary": summary}
	writeJSON(w, http.StatusOK, map[string]any{"created": len(created), "createdUsers": created, "results": results})
}

// createAzureAccount returns "" when the account was created, "exists" when an
// account has the name or the object id already, else a reason code.
func (s *Server) createAzureAccount(ctx context.Context, u auth.GraphUser, groupIDs []int) string {
	exists, err := s.store.DirectoryAccountExists(ctx, u.Username, u.ID)
	if err != nil {
		return problem.InternalError
	}
	if exists {
		return "exists"
	}
	hash, err := auth.HashPassword(randomPassword())
	if err == nil {
		_, err = s.store.CreateDirectoryUser(ctx, u.Username, hash, models.AuthSourceAzure, u.ID, groupIDs)
	}
	if err != nil {
		slog.Warn("Azure AD import failed", slog.String("user", u.Username), slog.Any("error", err))
		return problem.InternalError
	}
	return ""
}
