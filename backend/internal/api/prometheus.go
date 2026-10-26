package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/prom"
)

// Per-cluster Prometheus settings (Admin → Clusters). Secrets are write-only:
// reads return secretMask in their place, and a write that sends the mask
// back keeps the stored value.

const secretMask = "••••••••"

func maskPrometheus(c models.PrometheusConfig) models.PrometheusConfig {
	for _, f := range []*string{&c.Password, &c.Token, &c.AzureClientSecret, &c.ClientKey} {
		if *f != "" {
			*f = secretMask
		}
	}
	headers := make([]models.Header, len(c.Headers))
	for i, h := range c.Headers {
		headers[i] = models.Header{Name: h.Name, Value: secretMask}
	}
	c.Headers = headers
	return c
}

// keepSecrets puts stored secrets back where the client sent the mask.
func keepSecrets(in, stored models.PrometheusConfig) models.PrometheusConfig {
	pairs := [][2]*string{
		{&in.Password, &stored.Password},
		{&in.Token, &stored.Token},
		{&in.AzureClientSecret, &stored.AzureClientSecret},
		{&in.ClientKey, &stored.ClientKey},
	}
	for _, p := range pairs {
		if *p[0] == secretMask {
			*p[0] = *p[1]
		}
	}
	old := map[string]string{}
	for _, h := range stored.Headers {
		old[strings.ToLower(h.Name)] = h.Value
	}
	for i, h := range in.Headers {
		if h.Value == secretMask {
			in.Headers[i].Value = old[strings.ToLower(h.Name)]
		}
	}
	return in
}

func (s *Server) clusterParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid cluster id")
		return 0, false
	}
	return id, true
}

func (s *Server) handleGetPrometheus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clusterParam(w, r)
	if !ok {
		return
	}
	cfg, err := s.store.GetPrometheus(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}
	writeJSON(w, http.StatusOK, maskPrometheus(cfg))
}

func (s *Server) handlePutPrometheus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clusterParam(w, r)
	if !ok {
		return
	}
	stored, err := s.store.GetPrometheus(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}
	var in models.PrometheusConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	in = keepSecrets(in, stored)
	if in.Mode == "" {
		in = models.PrometheusConfig{}
	} else if _, err := prom.New(in, nil); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SetPrometheus(r.Context(), id, in); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	s.prom.Delete(id)
	s.overviewHistory.Delete(id)
	name, _ := s.store.GetClusterName(r.Context(), id)
	s.auditEvent(r, models.AuditLog{
		Verb:         audit.VerbUpdate,
		ResourceType: audit.KindCluster,
		ResourceName: name,
		Cluster:      name,
		ClusterID:    id,
		Details:      audit.D{"changed": []string{"prometheus"}},
	})
	writeJSON(w, http.StatusOK, maskPrometheus(in))
}

// handleTestPrometheus diagnoses the settings in the body (saved or not),
// using the stored secrets wherever the form still shows the mask.
func (s *Server) handleTestPrometheus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clusterParam(w, r)
	if !ok {
		return
	}
	stored, err := s.store.GetPrometheus(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}
	var in models.PrometheusConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	c, err := s.promClientFor(r.Context(), id, keepSecrets(in, stored))
	if err != nil {
		writeJSON(w, http.StatusOK, prom.Diagnosis{Steps: []prom.Step{{ID: "config", Status: "fail", Reason: "invalid", Detail: err.Error()}}})
		return
	}
	writeJSON(w, http.StatusOK, c.Diagnose(r.Context()))
}

func (s *Server) promClientFor(ctx context.Context, clusterID int, cfg models.PrometheusConfig) (*prom.Client, error) {
	m, err := s.clusters.Get(ctx, clusterID)
	if err != nil {
		return prom.New(cfg, nil)
	}
	client, _ := m.Client()
	return prom.New(cfg, client)
}

type promCandidate struct {
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	Port      string `json:"port"`
}

// handleDiscoverPrometheus lists the cluster's Services that look like a
// Prometheus (operator label, name, or port 9090), regular ones first.
func (s *Server) handleDiscoverPrometheus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clusterParam(w, r)
	if !ok {
		return
	}
	m, err := s.clusters.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "cluster not connected")
		return
	}
	client, ok := m.Client()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "cluster not connected")
		return
	}
	svcs, err := client.CoreV1().Services("").List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeKubeError(w, err, "services")
		return
	}
	type ranked struct {
		promCandidate
		score int
	}
	var found []ranked
	for _, svc := range svcs.Items {
		name := strings.ToLower(svc.Name)
		looks := svc.Labels["operated-prometheus"] == "true" || svc.Labels["app.kubernetes.io/name"] == "prometheus" ||
			(strings.Contains(name, "prometheus") && !strings.Contains(name, "alertmanager") &&
				!strings.Contains(name, "operator") && !strings.Contains(name, "node-exporter") &&
				!strings.Contains(name, "kube-state") && !strings.Contains(name, "pushgateway") && !strings.Contains(name, "adapter"))
		if !looks {
			continue
		}
		for _, p := range svc.Spec.Ports {
			if p.Port != 9090 && p.Name != "web" && p.Name != "http-web" {
				continue
			}
			score := 0
			if svc.Spec.ClusterIP == "None" {
				score = 1 // headless (prometheus-operated) works too, but a regular Service is the stable choice
			}
			found = append(found, ranked{promCandidate{svc.Namespace, svc.Name, strconv.Itoa(int(p.Port))}, score})
			break
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].score < found[j].score })
	out := make([]promCandidate, len(found))
	for i, f := range found {
		out[i] = f.promCandidate
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// promFor returns the request cluster's Prometheus client, or nil when the
// cluster has none configured.
func (s *Server) promFor(r *http.Request) *prom.Client {
	id := clusterIDFrom(r.Context())
	if id <= 0 {
		return nil
	}
	if c, ok := s.prom.Load(id); ok {
		cl, _ := c.(*prom.Client)
		return cl
	}
	cfg, err := s.store.GetPrometheus(r.Context(), id)
	if err != nil || cfg.Mode == "" {
		s.prom.Store(id, (*prom.Client)(nil))
		return nil
	}
	client, _ := kubeFor(r).Client()
	c, err := prom.New(cfg, client)
	if err != nil {
		return nil
	}
	s.prom.Store(id, c)
	return c
}
