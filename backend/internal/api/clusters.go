package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/models"
)

// Minimal multi-cluster management: operators save N cluster definitions and
// pick which one is "active" at any time. Per-user-per-cluster permissions
// remain a future milestone — today, admin controls the active cluster and
// every authenticated user queries whichever cluster is currently active.

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

// handleListClustersPublic returns id+name+isActive only, for the header
// dropdown that any authenticated user can see.
func (s *Server) handleListClustersPublic(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListClusters(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	type lite struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		IsActive bool   `json:"isActive"`
	}
	out := make([]lite, 0, len(items))
	for _, c := range items {
		out = append(out, lite{ID: c.ID, Name: c.Name, IsActive: c.IsActive})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleGetActiveCluster is exposed to any authenticated user so the UI header
// can show the active cluster name without needing admin.
func (s *Server) handleGetActiveCluster(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetActiveCluster(r.Context())
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
	if err := s.kube.ValidateCredentials(creds); err != nil {
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
		ResourceType: "cluster", ResourceName: p.Name,
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
		if err := s.kube.ValidateCredentials(creds); err != nil {
			writeError(w, http.StatusBadRequest, "cluster validation failed: "+err.Error())
			return
		}
	}
	if err := s.store.UpdateCluster(r.Context(), id, p.Name, p.Description, creds, p.ReplaceSecrets); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update cluster")
		return
	}
	// If this is the active cluster and we replaced creds, re-apply them.
	if p.ReplaceSecrets {
		if active, err := s.store.GetActiveCluster(r.Context()); err == nil && active.ID == id {
			_ = s.kube.ApplyCredentials(active.Credentials)
		}
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.update", Namespace: "-",
		ResourceType: "cluster", ResourceName: p.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteCluster(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.delete", Namespace: "-",
		ResourceType: "cluster", ResourceName: strconv.Itoa(id),
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
	// Tell the running Manager to drop its credentials so no further API calls
	// hit the previous cluster.
	_ = s.kube.ApplyCredentials(models.KubeCredentials{Method: "token", Server: "", Token: []byte{}})
	s.activeClusterID.Store(0)
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.deactivate", Namespace: "-",
		ResourceType: "cluster", ResourceName: strconv.Itoa(id),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleActivateCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.ActivateCluster(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := s.store.GetCluster(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cluster vanished after activation")
		return
	}
	if err := s.kube.ApplyCredentials(c.Credentials); err != nil {
		writeError(w, http.StatusBadGateway, "activation failed: "+err.Error())
		return
	}
	if err := s.kube.Start(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, "cluster start failed: "+err.Error())
		return
	}
	s.activeClusterID.Store(int64(c.ID))
	user, _ := s.userForRequest(r)
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User: userName(user), Action: "cluster.activate", Namespace: "-",
		ResourceType: "cluster", ResourceName: c.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": c.Name})
}

func userName(u *models.User) string {
	if u == nil {
		return ""
	}
	return u.Username
}
