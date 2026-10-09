package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// Multi-cluster management. Admins save N cluster definitions and mark one as
// the default ("active" in the API, kept for compatibility). Every user then
// picks their own cluster in the header (POST /api/cluster/select, see
// cluster_ctx.go); users who never picked one work on the default.

type clusterPayload struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Method           string `json:"method"`
	KubeconfigBase64 string `json:"kubeconfigBase64"`
	Token            string `json:"token"`
	Server           string `json:"server"`
	CACertBase64     string `json:"caCertBase64"`
	// ReplaceSecrets=true on update means the client is sending new creds;
	// false (default) preserves the existing encrypted blobs.
	ReplaceSecrets bool `json:"replaceSecrets"`
}

func (p clusterPayload) toCreds() (models.KubeCredentials, error) {
	creds := models.KubeCredentials{Method: p.Method, Server: p.Server}
	if p.KubeconfigBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(p.KubeconfigBase64)
		if err != nil {
			return creds, err
		}
		creds.Kubeconfig = data
	}
	if p.Token != "" {
		creds.Token = []byte(p.Token)
	}
	if p.CACertBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(p.CACertBase64)
		if err != nil {
			return creds, err
		}
		creds.CACert = data
	}
	if p.Method == "kubeconfig" && len(creds.Kubeconfig) == 0 {
		return creds, errors.New("kubeconfig is required")
	}
	if p.Method == "token" && (p.Server == "" || len(creds.Token) == 0) {
		return creds, errors.New("token method requires server and token")
	}
	return creds, nil
}

func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListClusters(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list clusters")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleListClustersPublic feeds the header switcher: the clusters the
// caller may use (admins: all; others: clusters their grants cover).
// isActive marks the default cluster, selected the caller's current one.
func (s *Server) handleListClustersPublic(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	items, err := s.store.ListClusters(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	current := clusterIDFrom(r.Context())
	type lite struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		IsActive bool   `json:"isActive"`
		Selected bool   `json:"selected"`
	}
	out := make([]lite, 0, len(items))
	for _, c := range items {
		if !s.canUseCluster(r.Context(), user, c.ID) {
			continue
		}
		out = append(out, lite{ID: c.ID, Name: c.Name, IsActive: c.IsActive, Selected: c.ID == current})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleGetActiveCluster returns the caller's current cluster (their own
// pick, else the default).
func (s *Server) handleGetActiveCluster(w http.ResponseWriter, r *http.Request) {
	ci := clusterFrom(r.Context())
	if ci.ID == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"active": nil})
		return
	}
	c, err := s.store.GetCluster(r.Context(), ci.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": map[string]any{
			"id":          c.ID,
			"name":        c.Name,
			"description": c.Description,
			"server":      c.Server,
			"method":      c.Method,
			"isDefault":   c.ID == s.DefaultClusterID(),
		},
	})
}

func (s *Server) handleCreateCluster(w http.ResponseWriter, r *http.Request) {
	var p clusterPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	creds, err := p.toCreds()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate credentials against the cluster BEFORE persisting; a bad kubeconfig
	// should fail here rather than silently stuck in the DB.
	if err := kube.ValidateCredentials(creds); err != nil {
		writeError(w, http.StatusBadRequest, "cluster validation failed: "+err.Error())
		return
	}
	id, err := s.store.CreateCluster(r.Context(), p.Name, p.Description, creds)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save cluster")
		return
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.create", Namespace: "-",
		ResourceType: "cluster", ResourceName: p.Name, Cluster: p.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleUpdateClusterByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p clusterPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	creds, cErr := p.toCreds()
	if p.ReplaceSecrets && cErr != nil {
		writeError(w, http.StatusBadRequest, cErr.Error())
		return
	}
	if p.ReplaceSecrets {
		if err := kube.ValidateCredentials(creds); err != nil {
			writeError(w, http.StatusBadRequest, "cluster validation failed: "+err.Error())
			return
		}
	}
	if err := s.store.UpdateCluster(r.Context(), id, p.Name, p.Description, creds, p.ReplaceSecrets); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update cluster")
		return
	}
	// New credentials: drop the live connection; the next request for this
	// cluster reconnects with what was just stored.
	if p.ReplaceSecrets {
		s.clusters.Invalidate(id)
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.update", Namespace: "-",
		ResourceType: "cluster", ResourceName: p.Name, Cluster: p.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name, _ := s.store.GetClusterName(r.Context(), id)
	if err := s.store.DeleteCluster(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.clusters.Invalidate(id)
	// Users who had picked it fall back to the default cluster.
	_ = s.store.ClearClusterSelections(r.Context(), id)
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.delete", Namespace: "-",
		ResourceType: "cluster", ResourceName: strconv.Itoa(id), Cluster: name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeactivateCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeactivateCluster(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Only the default changes: users who picked this cluster explicitly
	// keep working on it.
	s.defaultClusterID.Store(0)
	name, _ := s.store.GetClusterName(r.Context(), id)
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.deactivate", Namespace: "-",
		ResourceType: "cluster", ResourceName: strconv.Itoa(id), Cluster: name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleActivateCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name, err := s.store.GetClusterName(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}
	// Connect first: a cluster that can't be reached must not become the
	// default every new user lands on.
	if _, err := s.clusters.Get(r.Context(), id); err != nil {
		writeError(w, http.StatusBadGateway, "activation failed: "+err.Error())
		return
	}
	if err := s.store.ActivateCluster(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.defaultClusterID.Store(int64(id))
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.activate", Namespace: "-",
		ResourceType: "cluster", ResourceName: name, Cluster: name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": name})
}

func userName(u *models.User) string {
	if u == nil {
		return ""
	}
	return u.Username
}
