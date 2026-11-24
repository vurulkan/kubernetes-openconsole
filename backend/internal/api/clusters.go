package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
	"k8s-dashboard/backend/internal/store"
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
	// RemoveCACert on a token update drops the stored CA; without it an
	// empty caCertBase64 keeps the CA the cluster already has.
	RemoveCACert bool `json:"removeCaCert"`
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
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to list clusters")
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
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
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
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	if p.Name == "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "name is required")
		return
	}
	creds, err := p.toCreds()
	if err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, err.Error())
		return
	}
	// Validate credentials against the cluster BEFORE persisting; a bad kubeconfig
	// should fail here rather than silently stuck in the DB.
	if err := kube.ValidateCredentials(creds); err != nil {
		writeClusterValidationError(w, err)
		return
	}
	id, err := s.store.CreateCluster(r.Context(), p.Name, p.Description, creds)
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to save cluster")
		return
	}
	// Connected right away, like the clusters connected at start: its cache
	// warms up and openconsole_cluster_connected reports it before anyone picks it.
	_, _ = s.clusters.Get(r.Context(), id)
	s.recordClusterAudit(r, audit.VerbCreate, p.Name, id)
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleUpdateClusterByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var p clusterPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	creds, cErr := p.toCreds()
	if p.ReplaceSecrets && cErr != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, cErr.Error())
		return
	}
	if p.ReplaceSecrets && p.Method == "token" && len(creds.CACert) == 0 && !p.RemoveCACert {
		// A new token, the same API server certificate: keep the stored CA.
		old, err := s.store.GetCluster(r.Context(), id)
		if err != nil {
			writeErrorDetail(w, http.StatusNotFound, problem.NotFound, "cluster not found")
			return
		}
		creds.CACert = old.Credentials.CACert
	}
	if p.ReplaceSecrets {
		if err := kube.ValidateCredentials(creds); err != nil {
			writeClusterValidationError(w, err)
			return
		}
	}
	if err := s.store.UpdateCluster(r.Context(), id, p.Name, p.Description, creds, p.ReplaceSecrets); err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to update cluster")
		return
	}
	// New credentials: drop the live connection; the next request for this
	// cluster reconnects with what was just stored.
	if p.ReplaceSecrets {
		s.clusters.Invalidate(id)
		s.prom.Delete(id)
		s.dropHistory(id)
		_, _ = s.clusters.Get(r.Context(), id)
	}
	s.recordClusterAudit(r, audit.VerbUpdate, p.Name, id)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	name, _ := s.store.GetClusterName(r.Context(), id)
	if err := s.store.DeleteCluster(r.Context(), id); err != nil {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, err.Error())
		return
	}
	s.clusters.Invalidate(id)
	s.prom.Delete(id)
	s.dropHistory(id)
	// Users who had picked it fall back to the default cluster.
	_ = s.store.ClearClusterSelections(r.Context(), id)
	s.recordClusterAudit(r, audit.VerbDelete, name, id)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeactivateCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	if err := s.store.DeactivateCluster(r.Context(), id); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, err.Error())
		return
	}
	// Only the default changes: users who picked this cluster explicitly
	// keep working on it.
	s.defaultClusterID.Store(0)
	name, _ := s.store.GetClusterName(r.Context(), id)
	s.recordClusterAudit(r, audit.VerbDeactivate, name, id)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleActivateCluster(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	name, err := s.store.GetClusterName(r.Context(), id)
	if err != nil {
		writeErrorDetail(w, http.StatusNotFound, problem.NotFound, "cluster not found")
		return
	}
	// Connect first: a cluster that can't be reached must not become the
	// default every new user lands on.
	m, err := s.clusters.Get(r.Context(), id)
	if err == nil {
		err = m.Check(r.Context())
	}
	if err != nil {
		writeErrorDetail(w, http.StatusBadGateway, problem.ClusterInvalid, "activation failed: "+err.Error())
		return
	}
	if err := s.store.ActivateCluster(r.Context(), id); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, err.Error())
		return
	}
	s.defaultClusterID.Store(int64(id))
	s.recordClusterAudit(r, audit.VerbActivate, name, id)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": name})
}

// handlePutClusterOrder saves the order clusters are listed in everywhere
// (switcher, palette, API key form, Admin → Clusters). The body names every
// cluster once; a list that no longer matches the saved clusters is 409.
func (s *Server) handlePutClusterOrder(w http.ResponseWriter, r *http.Request) {
	noteFor(r).Name = "order"
	var body struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	seen := map[int]bool{}
	for _, id := range body.IDs {
		if id <= 0 || seen[id] {
			writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "ids must name every cluster once")
			return
		}
		seen[id] = true
	}
	if err := s.store.SetClusterOrder(r.Context(), body.IDs); err != nil {
		if errors.Is(err, store.ErrClusterOrderStale) {
			writeErrorDetail(w, http.StatusConflict, problem.Conflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	noteFor(r).Details = audit.D{"count": len(body.IDs)}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// recordClusterAudit records an admin action on a cluster; the cluster is
// the target, so it is recorded as the event's cluster too.
func (s *Server) recordClusterAudit(r *http.Request, verb, name string, id int) {
	s.auditEvent(r, models.AuditLog{
		Verb:         verb,
		ResourceType: audit.KindCluster,
		ResourceName: name,
		Cluster:      name,
		ClusterID:    id,
	})
}

// clusterValidationError is the 400 message for credentials that don't
// validate; a kubeconfig that runs a program or reads a file starts with the
// reason code kubeconfig_unsupported.
func writeClusterValidationError(w http.ResponseWriter, err error) {
	if errors.Is(err, kube.ErrKubeconfigUnsupported) {
		writeErrorDetail(w, http.StatusBadRequest, problem.KubeconfigUnsupported,
			strings.TrimPrefix(err.Error(), problem.KubeconfigUnsupported+": "))
		return
	}
	writeErrorDetail(w, http.StatusBadRequest, problem.ClusterInvalid, err.Error())
}
