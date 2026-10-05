package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"k8s-dashboard/backend/internal/logging"
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
	s.recordAudit(r, "list", namespace, "daemonsets", "*")
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
	s.recordAudit(r, "get", namespace, "daemonsets", item.Name)
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
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
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
	s.recordAudit(r, "list", namespace, "statefulsets", "*")
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
	s.recordAudit(r, "get", namespace, "statefulsets", item.Name)
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
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
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
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), user.ID, namespace, "statefulsets", "scale") {
		s.recordWorkloadAudit(user.Username, namespace, name, "statefulset", "statefulset.scale", "denied", "", requestID)
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
		s.recordWorkloadAudit(user.Username, namespace, name, "statefulset", "statefulset.scale", "rate_limited", "", requestID)
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	previous, err := s.resources.ScaleStatefulSet(r.Context(), namespace, name, body.Replicas)
	if err != nil {
		slog.ErrorContext(r.Context(), "statefulset.scale.failed",
			slog.String("user", user.Username),
			slog.String("namespace", namespace),
			slog.String("statefulset", name),
			slog.Int("target_replicas", int(body.Replicas)),
			slog.Any("error", err),
			slog.String("request_id", requestID),
		)
		s.recordWorkloadAudit(user.Username, namespace, name, "statefulset", "statefulset.scale", "failed",
			fmt.Sprintf("from=%d to=%d err=%s", previous, body.Replicas, err.Error()), requestID)
		writeError(w, http.StatusBadGateway, "scale failed")
		return
	}

	s.recordWorkloadAudit(user.Username, namespace, name, "statefulset", "statefulset.scale", "success",
		fmt.Sprintf("from=%d to=%d", previous, body.Replicas), requestID)
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
	s.recordAudit(r, "list", namespace, "hpas", "*")
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
	s.recordAudit(r, "get", namespace, "hpas", item.Name)
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
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) recordWorkloadAudit(user, namespace, name, resourceType, action, outcome, details, requestID string) {
	resourceName := name
	if details != "" {
		resourceName = fmt.Sprintf("%s (%s)", name, details)
	}
	go s.audit.Record(s.auditCtxFromID(requestID), models.AuditLog{
		User:         user,
		Action:       action + "." + outcome,
		Namespace:    namespace,
		ResourceType: resourceType,
		ResourceName: resourceName,
	})
	slog.Info("workload.action",
		slog.String("event", action),
		slog.String("outcome", outcome),
		slog.String("user", user),
		slog.String("namespace", namespace),
		slog.String("resource", resourceType),
		slog.String("name", name),
		slog.String("details", details),
		slog.String("request_id", requestID),
	)
}
