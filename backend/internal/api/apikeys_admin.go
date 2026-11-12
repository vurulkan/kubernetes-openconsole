package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
)

// Admin view of every user's API keys (M15): list, CSV, revoke one or all of
// a user's, and the API access preview of the user drawer. An admin never
// edits another user's key and never sees a secret (only the prefix). Key
// management is web-session only, also for admins (denyAPIKey).

type adminAPIKeyView struct {
	models.APIKey
	OwnerID int    `json:"ownerId"`
	Owner   string `json:"owner"`
	// Status: active | expired | revoked.
	Status string `json:"status"`
	// OutsidePolicy: an active key the expiry policy would not allow today
	// (too long, or never expiring when that is off). Left alone, listed for review.
	OutsidePolicy bool `json:"outsidePolicy"`
}

func keyStatus(k models.APIKey, now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return "revoked"
	case k.ExpiresAt != nil && !now.Before(*k.ExpiresAt):
		return "expired"
	}
	return "active"
}

// adminKeyViews returns every key with its owner, newest first.
func (s *Server) adminKeyViews(r *http.Request) ([]adminAPIKeyView, error) {
	ctx := r.Context()
	keys, err := s.store.ListAPIKeys(ctx, 0)
	if err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := s.store.GetSessionSettings(ctx)
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	now := time.Now()
	out := make([]adminAPIKeyView, 0, len(keys))
	for _, k := range keys {
		v := adminAPIKeyView{APIKey: k, OwnerID: k.UserID, Owner: names[k.UserID], Status: keyStatus(k, now)}
		v.OutsidePolicy = v.Status == "active" && expiryError(policy, k.ExpiresAt, now) != nil
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) handleAdminListAPIKeys(w http.ResponseWriter, r *http.Request) {
	e := models.AuditLog{Verb: audit.VerbList, ResourceType: audit.KindAPIKey, ResourceName: "*"}
	if s.denyAPIKey(w, r, e) {
		return
	}
	items, err := s.adminKeyViews(r)
	if err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "could not list API keys")
		return
	}
	e.Details = audit.D{"count": len(items)}
	s.auditEvent(r, e)
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleExportAPIKeys(w http.ResponseWriter, r *http.Request) {
	e := models.AuditLog{Verb: audit.VerbExport, ResourceType: audit.KindAPIKey, ResourceName: "*"}
	if s.denyAPIKey(w, r, e) {
		return
	}
	items, err := s.adminKeyViews(r)
	if err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "could not list API keys")
		return
	}
	at := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.In(s.timezone).Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=api-keys.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"owner", "name", "prefix", "status", "outside_expiry_policy", "admin_scope", "scope",
		"created_at", "last_used_at", "last_used_ip", "expires_at", "revoked_at"})
	for _, k := range items {
		_ = cw.Write([]string{k.Owner, k.Name, k.Prefix, k.Status, strconv.FormatBool(k.OutsidePolicy), strconv.FormatBool(k.AdminScope),
			keySummary(k.APIKey), at(&k.CreatedAt), at(k.LastUsedAt), k.LastUsedIP, at(k.ExpiresAt), at(k.RevokedAt)})
	}
	cw.Flush()
	e.Details = audit.D{"count": len(items)}
	s.auditEvent(r, e)
}

// handleAdminRevokeAPIKey revokes another user's (or the admin's own) key,
// with an optional comment for the audit log.
func (s *Server) handleAdminRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	e := models.AuditLog{Verb: audit.VerbRevoke, ResourceType: audit.KindAPIKey, ResourceName: chi.URLParam(r, "id")}
	if s.denyAPIKey(w, r, e) {
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Comment string `json:"comment"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
	}
	body.Comment = strings.TrimSpace(body.Comment)
	if len(body.Comment) > 500 {
		writeError(w, http.StatusBadRequest, "the comment is too long (at most 500 characters)")
		return
	}
	k, err := s.store.GetAPIKey(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "API key not found")
		return
	}
	owner := "id:" + strconv.Itoa(k.UserID)
	if u, err := s.store.GetUserByID(r.Context(), k.UserID); err == nil {
		owner = u.Username
	}
	e.ResourceName = k.Name
	e.Details = audit.D{"id": k.ID, "owner": owner, "by_admin": true}
	if body.Comment != "" {
		e.Details["comment"] = body.Comment
	}
	if keyStatus(*k, time.Now()) != "active" {
		e.Outcome, e.Reason = audit.Failed, "not_active"
		s.auditEvent(r, e)
		writeError(w, http.StatusConflict, "the key is already revoked or expired")
		return
	}
	if err := s.store.RevokeAPIKey(r.Context(), k.ID); err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, e.Details)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "could not revoke the key")
		return
	}
	s.auditEvent(r, e)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleRevokeUserAPIKeys revokes every active key of a user (the sessions'
// "revoke all" pattern): one audit entry with the count.
func (s *Server) handleRevokeUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	e := models.AuditLog{Verb: audit.VerbRevoke, ResourceType: audit.KindAPIKey, ResourceName: "*"}
	if s.denyAPIKey(w, r, e) {
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	e.Details = audit.D{"owner": u.Username, "all": true, "by_admin": true}
	n, err := s.store.RevokeUserAPIKeys(r.Context(), id)
	if err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, e.Details)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "could not revoke the keys")
		return
	}
	e.Details["count"] = n
	s.auditEvent(r, e)
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

type previewNamespace struct {
	ClusterID int    `json:"clusterId"`
	Namespace string `json:"namespace"`
	// Level: all (every grant the user holds here) | read (safe read-only
	// only) | partial | none.
	Level string `json:"level"`
}

// handleUserAPIAccess previews what the user's API keys may reach, per
// namespace, under the saved override or ?override= (a choice not saved yet).
func (s *Server) handleUserAPIAccess(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	e := models.AuditLog{Verb: audit.VerbGet, ResourceType: audit.KindUser, ResourceName: u.Username}
	if q := r.URL.Query(); q.Has("override") {
		u.APIAccessOverride = q.Get("override")
		if u.APIAccessOverride != "" && !rbac.ValidMode(u.APIAccessOverride) {
			writeError(w, http.StatusBadRequest, errAPIAccess)
			return
		}
	}
	fail := func(err error) {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "could not compute the API access")
	}
	refused, err := s.keysRefused(r.Context(), u)
	if err != nil {
		fail(err)
		return
	}
	keys, err := s.store.ListAPIKeys(r.Context(), u.ID)
	if err != nil {
		fail(err)
		return
	}
	now := time.Now()
	out := map[string]any{"isAdmin": u.IsAdmin, "refused": refused,
		"activeKeys": len(slices.DeleteFunc(keys, func(k models.APIKey) bool { return keyStatus(k, now) != "active" }))}
	if u.IsAdmin {
		// Every namespace: one line, the admin's own mode.
		out["adminMode"] = rbac.AdminKeyMode(u.APIAccessOverride)
		s.auditEvent(r, e)
		writeJSON(w, http.StatusOK, out)
		return
	}
	ceiling, err := s.ceilingFor(r.Context(), u)
	if err != nil {
		fail(err)
		return
	}
	nss := make([]previewNamespace, 0, len(ceiling.Namespaces))
	for _, n := range ceiling.Namespaces {
		level := "partial"
		switch {
		case len(n.Grants) == 0:
			level = "none"
		case len(n.Blocked) == 0:
			level = "all"
		case !slices.ContainsFunc(n.Grants, func(g string) bool { return !slices.Contains(ceiling.SafeRead, g) }):
			level = "read"
		}
		nss = append(nss, previewNamespace{ClusterID: n.ClusterID, Namespace: n.Namespace, Level: level})
	}
	out["clusters"], out["namespaces"] = ceiling.Clusters, nss
	s.auditEvent(r, e)
	writeJSON(w, http.StatusOK, out)
}
