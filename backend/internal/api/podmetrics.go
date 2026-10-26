package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/prom"
)

// Pod CPU / memory. Reads are not audited (like events): the UI polls them
// next to the pod list, which is audited itself.

var memoryRanges = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour}

func (s *Server) handlePodMetrics(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "list")
	if !ok {
		return
	}
	m := kubeFor(r).Metrics()
	if m == nil {
		writeJSON(w, http.StatusOK, kube.Snapshot{Reason: "not_connected", Items: []kube.PodUsage{}})
		return
	}
	writeJSON(w, http.StatusOK, m.Namespace(namespace))
}

type historyResponse struct {
	Source string   `json:"source"` // prometheus | memory
	Note   string   `json:"note,omitempty"`
	Ranges []string `json:"ranges"`
	Points any      `json:"points"`
}

// history answers ?range= from the cluster's Prometheus when one is
// configured, else (or when it fails) from the in-memory sampler.
func (s *Server) history(w http.ResponseWriter, r *http.Request, podRegex func() string,
	memory func(m *kube.MetricsSampler, rng time.Duration) []kube.Point) {
	rng := r.URL.Query().Get("range")
	note := ""
	if c := s.promFor(r); c != nil {
		pts, err := c.History(r.Context(), chi.URLParam(r, "namespace"), podRegex(), rng, time.Now())
		if err == nil {
			writeJSON(w, http.StatusOK, historyResponse{Source: "prometheus", Ranges: []string{"1h", "6h", "24h", "7d"}, Points: pts})
			return
		}
		slog.Warn("prometheus query failed; using in-memory samples", slog.Any("error", err))
		note = "prometheus_unreachable"
	}
	span, ok := memoryRanges[rng]
	if !ok {
		span = 24 * time.Hour
	}
	var pts []kube.Point
	if m := kubeFor(r).Metrics(); m != nil {
		pts = memory(m, span)
	}
	if pts == nil {
		pts = []kube.Point{}
	}
	writeJSON(w, http.StatusOK, historyResponse{Source: "memory", Note: note, Ranges: []string{"1h", "6h", "24h"}, Points: pts})
}

func (s *Server) handlePodMetricsHistory(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "list")
	if !ok {
		return
	}
	name := chi.URLParam(r, "name")
	s.history(w, r, func() string { return prom.PodRegex(name) },
		func(m *kube.MetricsSampler, rng time.Duration) []kube.Point {
			return m.PodHistory(namespace, name, rng, time.Now())
		})
}

// workloadKinds maps the URL segment to the owner kind and the permission resource.
var workloadKinds = map[string]string{"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet"}

// handleWorkloadMetricsHistory sums a Deployment's, StatefulSet's or
// DaemonSet's pods (needs <kind>:get).
func (s *Server) handleWorkloadMetricsHistory(resource string) http.HandlerFunc {
	kind := workloadKinds[resource]
	return func(w http.ResponseWriter, r *http.Request) {
		namespace, ok := s.requirePermission(w, r, resource, "get")
		if !ok {
			return
		}
		name := chi.URLParam(r, "name")
		s.history(w, r,
			func() string {
				switch kind {
				case "StatefulSet":
					return prom.StatefulSetRegex(name)
				case "DaemonSet":
					return prom.DaemonSetRegex(name)
				}
				// Old revisions' pods count too, so a crash after a rollout shows up next to the one before.
				var hashes []string
				if sets, err := s.resources.ListDeploymentReplicaSets(r.Context(), namespace, name); err == nil {
					for _, rs := range sets {
						if h := rs.Labels["pod-template-hash"]; h != "" {
							hashes = append(hashes, h)
						}
					}
				}
				return prom.DeploymentRegex(name, hashes)
			},
			func(m *kube.MetricsSampler, rng time.Duration) []kube.Point {
				return m.OwnerHistory(namespace, kind+"/"+name, rng, time.Now())
			})
	}
}
