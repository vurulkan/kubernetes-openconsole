package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/problem"
)

func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	existing, err := s.resources.ListNamespaces(r.Context())
	if err != nil {
		writeReadError(w, r, err, "namespaces")
		return
	}
	if _, ok := s.userForRequest(r); !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		writeError(w, http.StatusForbidden, reasonForbidden)
		return
	}
	var result []string
	for _, ns := range existing {
		if engine.SeesNamespace(clusterIDFrom(r.Context()), ns.Name) {
			result = append(result, ns.Name)
		}
	}
	s.auditRead(r, audit.VerbList, "namespaces", "", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"namespaces": result})
}

func (s *Server) handleNamespacePermissions(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	if _, ok := s.userForRequest(r); !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		writeError(w, http.StatusForbidden, reasonForbidden)
		return
	}
	permissions := s.filterByFeatures(engine.AllowedResources(clusterIDFrom(r.Context()), namespace))
	if len(permissions) == 0 {
		writeError(w, http.StatusForbidden, reasonForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"resources": permissions})
}

func (s *Server) handlePods(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "list")
	if !ok {
		return
	}
	pods, err := s.resources.ListPods(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "pods")
		return
	}
	s.auditRead(r, audit.VerbList, "pods", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": pods})
}

func (s *Server) handlePod(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	pod, err := s.resources.GetPod(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, "pods")
		return
	}
	s.auditRead(r, audit.VerbGet, "pods", namespace, pod.Name)
	writeJSON(w, http.StatusOK, pod)
}

func (s *Server) handleDeployments(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListDeployments(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "deployments")
		return
	}
	s.auditRead(r, audit.VerbList, "deployments", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleDeployment(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetDeployment(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, "deployments")
		return
	}
	s.auditRead(r, audit.VerbGet, "deployments", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "services", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListServices(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "services")
		return
	}
	s.auditRead(r, audit.VerbList, "services", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "services", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetService(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, "services")
		return
	}
	s.auditRead(r, audit.VerbGet, "services", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleConfigMaps(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListConfigMaps(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "configmaps")
		return
	}
	s.auditRead(r, audit.VerbList, "configmaps", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleConfigMap(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetConfigMap(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, "configmaps")
		return
	}
	s.auditRead(r, audit.VerbGet, "configmaps", namespace, item.Name)
	writeJSON(w, http.StatusOK, item)
}

// yamlObject is a typed client-go object (*corev1.Pod, …).
type yamlObject interface {
	metav1.Object
	runtime.Object
}

// serveYAML answers a namespaced object as YAML for the viewer / editor and
// records the read. Secrets have their own handler (values hidden).
//
// Typed client-go objects return with an empty TypeMeta (apiVersion/kind are
// omitempty on marshal), so without tm the YAML the UI shows is missing the
// first two lines — which also makes a round-trip POST .../apply fail at the
// API server with "object has no kind".
func serveYAML[T yamlObject](s *Server, w http.ResponseWriter, r *http.Request, resource string, tm metav1.TypeMeta,
	get func(context.Context, string, string) (T, error)) {
	namespace, ok := s.requirePermission(w, r, resource, "get")
	if !ok {
		return
	}
	item, err := get(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, resource)
		return
	}
	item.SetManagedFields(nil)
	item.GetObjectKind().SetGroupVersionKind(tm.GroupVersionKind())
	data, err := yaml.Marshal(item)
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to render yaml")
		return
	}
	s.auditRead(r, audit.VerbGet, resource, namespace, item.GetName())
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
}

func (s *Server) handlePodYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "pods", metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, s.resources.GetPod)
}

func (s *Server) handleDeploymentYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "deployments", metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, s.resources.GetDeployment)
}

func (s *Server) handleServiceYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "services", metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, s.resources.GetService)
}

func (s *Server) handleConfigMapYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "configmaps", metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, s.resources.GetConfigMap)
}

func (s *Server) handleConfigMapData(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetConfigMap(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeReadError(w, r, err, "configmaps")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": item.Data})
}

func (s *Server) handleIngresses(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "ingresses", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListIngresses(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "ingresses")
		return
	}
	s.auditRead(r, audit.VerbList, "ingresses", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleCronJobs(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "cronjobs", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListCronJobs(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "cronjobs")
		return
	}
	s.auditRead(r, audit.VerbList, "cronjobs", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleCronJobYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "cronjobs", metav1.TypeMeta{Kind: "CronJob", APIVersion: "batch/v1"}, s.resources.GetCronJob)
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "jobs", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListJobs(r.Context(), namespace)
	if err != nil {
		writeReadError(w, r, err, "jobs")
		return
	}
	s.auditRead(r, audit.VerbList, "jobs", namespace, "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleJobYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "jobs", metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"}, s.resources.GetJob)
}

func (s *Server) handleIngressYAML(w http.ResponseWriter, r *http.Request) {
	serveYAML(s, w, r, "ingresses", metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"}, s.resources.GetIngress)
}

func (s *Server) handlePodEvents(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	client, ok := kubeFor(r).Client()
	if !ok || !kubeFor(r).Ready() {
		writeError(w, http.StatusServiceUnavailable, problem.NotConnected)
		return
	}
	name := chi.URLParam(r, "name")
	events, err := client.CoreV1().Events(namespace).List(r.Context(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.kind=Pod,involvedObject.name=%s", name),
	})
	if err != nil {
		writeReadError(w, r, err, "events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": events.Items})
}

// handleWorkloadEvents lists a Deployment's, StatefulSet's or DaemonSet's own
// events (needs <kind>:get); its pods' events are on the pods.
func (s *Server) handleWorkloadEvents(resource string) http.HandlerFunc {
	kind := workloadKinds[resource]
	return func(w http.ResponseWriter, r *http.Request) {
		namespace, ok := s.requirePermission(w, r, resource, "get")
		if !ok {
			return
		}
		client, ok := kubeFor(r).Client()
		if !ok || !kubeFor(r).Ready() {
			writeError(w, http.StatusServiceUnavailable, problem.NotConnected)
			return
		}
		name := chi.URLParam(r, "name")
		events, err := client.CoreV1().Events(namespace).List(r.Context(), metav1.ListOptions{
			FieldSelector: fmt.Sprintf("involvedObject.kind=%s,involvedObject.name=%s", kind, name),
		})
		if err != nil {
			writeReadError(w, r, err, "events")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": events.Items})
	}
}
