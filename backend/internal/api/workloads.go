package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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

// replicaSetRevision is one Deployment revision as the detail view shows it.
type replicaSetRevision struct {
	Name          string   `json:"name"`
	Revision      string   `json:"revision"`
	Hash          string   `json:"podTemplateHash"`
	Images        []string `json:"images"`
	Replicas      int32    `json:"replicas"`
	ReadyReplicas int32    `json:"readyReplicas"`
	CreatedAt     string   `json:"createdAt"`
}

// handleDeploymentReplicaSets lists a Deployment's revisions (read-only; there
// is no rollback). Like the events endpoint it is part of the detail view and
// needs deployments:get.
func (s *Server) handleDeploymentReplicaSets(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "get")
	if !ok {
		return
	}
	sets, err := s.resources.ListDeploymentReplicaSets(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeKubeError(w, err, "replicasets")
		return
	}
	out := make([]replicaSetRevision, 0, len(sets))
	for _, rs := range sets {
		images := make([]string, 0, len(rs.Spec.Template.Spec.Containers))
		for _, c := range rs.Spec.Template.Spec.Containers {
			images = append(images, c.Image)
		}
		var replicas int32
		if rs.Spec.Replicas != nil {
			replicas = *rs.Spec.Replicas
		}
		out = append(out, replicaSetRevision{
			Name:          rs.Name,
			Revision:      rs.Annotations["deployment.kubernetes.io/revision"],
			Hash:          rs.Labels["pod-template-hash"],
			Images:        images,
			Replicas:      replicas,
			ReadyReplicas: rs.Status.ReadyReplicas,
			CreatedAt:     rs.CreationTimestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": out})
}

// Restart history (container exits recorded by the pod informers), newest first.
func (s *Server) restartHistory(w http.ResponseWriter, r *http.Request, namespace, deployment, pod string) {
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days <= 0 || days > 365 {
		days = 30
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	items, err := s.store.ListTerminations(r.Context(), clusterIDFrom(r.Context()), namespace, deployment, pod, since, 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read restart history")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handlePodRestarts(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	s.restartHistory(w, r, namespace, "", chi.URLParam(r, "name"))
}

// handleWorkloadRestarts: restart history of a Deployment's, StatefulSet's or
// DaemonSet's pods, those that no longer exist included (needs <kind>:get).
func (s *Server) handleWorkloadRestarts(resource string) http.HandlerFunc {
	kind := workloadKinds[resource]
	return func(w http.ResponseWriter, r *http.Request) {
		namespace, ok := s.requirePermission(w, r, resource, "get")
		if !ok {
			return
		}
		s.restartHistory(w, r, namespace, kind+"/"+chi.URLParam(r, "name"), "")
	}
}
