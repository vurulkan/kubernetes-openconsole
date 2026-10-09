package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/models"
)

// Saved views: named Dashboard filters stored per user (so they follow the
// user across browsers). A view remembers the cluster it was saved on; the
// owner can share it with everyone (read-only for others). Owners delete
// their views; admins can delete any shared view.

const maxViewNameLength = 80

func (s *Server) handleListViews(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	views, err := s.store.ListViewsFor(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load views")
		return
	}
	type item struct {
		models.SavedView
		Mine bool `json:"mine"`
	}
	out := make([]item, 0, len(views))
	for _, v := range views {
		out = append(out, item{SavedView: v, Mine: v.UserID == user.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleSaveView(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Tab       string `json:"tab"`
		Search    string `json:"search"`
		ViewMode  string `json:"viewMode"`
		Shared    bool   `json:"shared"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || utf8.RuneCountInString(body.Name) > maxViewNameLength {
		writeError(w, http.StatusBadRequest, "name is required (max "+strconv.Itoa(maxViewNameLength)+" characters)")
		return
	}
	if body.ViewMode != "list" {
		body.ViewMode = "card"
	}
	id, err := s.store.SaveView(r.Context(), models.SavedView{
		UserID:    user.ID,
		Name:      body.Name,
		ClusterID: clusterIDFrom(r.Context()),
		Namespace: body.Namespace,
		Tab:       body.Tab,
		Search:    body.Search,
		ViewMode:  body.ViewMode,
		Shared:    body.Shared,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save view")
		return
	}
	s.recordViewAudit(r, user.Username, "view.save", body.Name, "shared="+strconv.FormatBool(body.Shared))
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// handleShareView toggles sharing on one of the caller's views.
func (s *Server) handleShareView(w http.ResponseWriter, r *http.Request) {
	user, view, ok := s.viewForWrite(w, r, false)
	if !ok {
		return
	}
	var body struct {
		Shared bool `json:"shared"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.store.SetViewShared(r.Context(), view.ID, body.Shared); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update view")
		return
	}
	s.recordViewAudit(r, user.Username, "view.share", view.Name, "shared="+strconv.FormatBool(body.Shared))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteView(w http.ResponseWriter, r *http.Request) {
	user, view, ok := s.viewForWrite(w, r, true)
	if !ok {
		return
	}
	if err := s.store.DeleteView(r.Context(), view.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete view")
		return
	}
	s.recordViewAudit(r, user.Username, "view.delete", view.Name, "owner="+view.Owner)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// viewForWrite loads the view in the URL and checks the caller may change
// it: the owner, or (when adminMayAct) an admin for a shared view.
func (s *Server) viewForWrite(w http.ResponseWriter, r *http.Request, adminMayAct bool) (*models.User, *models.SavedView, bool) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, nil, false
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return nil, nil, false
	}
	view, err := s.store.GetView(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "view not found")
		return nil, nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load view")
		return nil, nil, false
	}
	owner := view.UserID == user.ID
	if !owner && !(adminMayAct && user.IsAdmin && view.Shared) {
		// Someone else's view: don't reveal private ones exist.
		if !view.Shared {
			writeError(w, http.StatusNotFound, "view not found")
			return nil, nil, false
		}
		s.recordViewAudit(r, user.Username, "view.change.denied", view.Name, "owner="+view.Owner)
		writeError(w, http.StatusForbidden, "only the owner can change this view")
		return nil, nil, false
	}
	return user, view, true
}

func (s *Server) recordViewAudit(r *http.Request, user, action, name, detail string) {
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         user,
		Action:       action,
		Namespace:    "-",
		ResourceType: "view",
		ResourceName: name + " (" + detail + ")",
	})
}
