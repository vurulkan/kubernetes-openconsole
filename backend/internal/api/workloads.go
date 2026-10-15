package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// Handlers for the newer workload tabs added in 2.4.0: DaemonSet,
// StatefulSet, HPA. They follow the same list/get/yaml shape as the earlier
// Deployment handlers; StatefulSet also gets a Scale endpoint that reuses
// the same per-user rate limiter as deployment.scale.

func (s *Server) handleDaemonSets(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "daemonsets", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListDaemonSets(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.auditRead(r, audit.VerbList, "daemonsets", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDaemonSet(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "daemonsets", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetDaemonSet(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.auditRead(r, audit.VerbGet, "daemonsets", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDaemonSetYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "daemonsets", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetDaemonSet(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	item.TypeMeta = metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
}

func (s *Server) handleStatefulSets(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "statefulsets", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListStatefulSets(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.auditRead(r, audit.VerbList, "statefulsets", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleStatefulSet(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "statefulsets", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetStatefulSet(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.auditRead(r, audit.VerbGet, "statefulsets", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleStatefulSetYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "statefulsets", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetStatefulSet(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	item.TypeMeta = metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
}

// handleStatefulSetScale mirrors handleDeploymentScale: same rate limiter
// bucket (per user), same MAX_REPLICAS cap, same audit outcome breakdown.
func (s *Server) handleStatefulSetScale(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	if !s.can(r.Context(), user.ID, namespace, "statefulsets", "scale") {
		s.recordStatefulSetScaleAudit(r, namespace, name, audit.Denied, reasonForbidden, nil)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var body struct {
		Replicas int32 `json:"replicas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	max := int32(defaultMaxReplicas)
	if v := strings.TrimSpace(os.Getenv("MAX_REPLICAS")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			max = int32(parsed)
		}
	}
	if body.Replicas < 0 || body.Replicas > max {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("replicas must be between 0 and %d", max))
		return
	}

	if !allowDeployAction(user.ID) {
		w.Header().Set("Retry-After", "6")
		s.recordStatefulSetScaleAudit(r, namespace, name, audit.RateLimited, reasonRateLimited, audit.D{"replicas_to": body.Replicas})
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	previous, err := s.resources.ScaleStatefulSet(r.Context(), namespace, name, body.Replicas)
	if err != nil {
		s.recordStatefulSetScaleAudit(r, namespace, name, audit.Failed, failReason(err),
			failDetails(err, audit.D{"replicas_from": previous, "replicas_to": body.Replicas}))
		writeActionError(w, err, "scale failed")
		return
	}

	s.recordStatefulSetScaleAudit(r, namespace, name, audit.Success, "",
		audit.D{"replicas_from": previous, "replicas_to": body.Replicas})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"previous": previous,
		"replicas": body.Replicas,
	})
}

func (s *Server) handleHPAs(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "hpas", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListHPAs(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.auditRead(r, audit.VerbList, "hpas", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleHPA(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "hpas", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetHPA(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.auditRead(r, audit.VerbGet, "hpas", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleHPAYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "hpas", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetHPA(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	item.TypeMeta = metav1.TypeMeta{Kind: "HorizontalPodAutoscaler", APIVersion: "autoscaling/v2"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
}

func (s *Server) recordStatefulSetScaleAudit(r *http.Request, namespace, name, outcome, reason string, details audit.D) {
	s.auditEvent(r, models.AuditLog{
		Verb:         audit.VerbScale,
		Outcome:      outcome,
		Reason:       reason,
		ResourceType: "statefulset",
		Namespace:    namespace,
		ResourceName: name,
		Details:      details,
	})
}
