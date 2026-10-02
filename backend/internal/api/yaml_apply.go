package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// resourceGVR maps the Dashboard's resource URL segment to the GVR the
// dynamic client needs. The subset here matches handleNamespacePermissions +
// the admin bypass list — everything the UI already shows a YAML button for.
var resourceGVR = map[string]schema.GroupVersionResource{
	"pods":         {Group: "", Version: "v1", Resource: "pods"},
	"services":     {Group: "", Version: "v1", Resource: "services"},
	"configmaps":   {Group: "", Version: "v1", Resource: "configmaps"},
	"deployments":  {Group: "apps", Version: "v1", Resource: "deployments"},
	"daemonsets":   {Group: "apps", Version: "v1", Resource: "daemonsets"},
	"statefulsets": {Group: "apps", Version: "v1", Resource: "statefulsets"},
	"hpas":         {Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"},
	"ingresses":    {Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"},
	"cronjobs":     {Group: "batch", Version: "v1", Resource: "cronjobs"},
	"jobs":         {Group: "batch", Version: "v1", Resource: "jobs"},
}

type applyRequest struct {
	YAML   string `json:"yaml"`
	DryRun bool   `json:"dryRun"`
}

// handleYAMLApply handles POST .../{resource}/{name}/apply for every workload
// listed in resourceGVR. The resource segment is pulled from the URL via chi's
// router pattern so we only need one handler, one permission check, one rate
// limiter path.
//
// Permission required: {resource}:edit  (admins bypass as usual)
// Rate limit: same per-user bucket as deployment.scale / restart.
// Audit: {resource}.apply.{success,denied,rate_limited,failed} with
//        from/to sha256 hashes of the YAML in the ResourceName field. Hashes
//        rather than full bodies keep the audit table small and non-leaky.
func (s *Server) handleYAMLApply(w http.ResponseWriter, r *http.Request) {
	resource := chi.URLParam(r, "resource")
	gvr, ok := resourceGVR[resource]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported resource type")
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !s.can(r.Context(), user.ID, namespace, resource, "edit") {
		s.recordApplyAudit(user.Username, namespace, name, resource, "denied", "", requestID)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var body applyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.YAML == "" {
		writeError(w, http.StatusBadRequest, "yaml is required")
		return
	}

	// Rate limit only the mutating path. Dry-run is cheap and operators
	// iterate on it; limiting the preview would make the UI feel broken.
	if !body.DryRun {
		if !allowDeployAction(user.ID) {
			w.Header().Set("Retry-After", "6")
			s.recordApplyAudit(user.Username, namespace, name, resource, "rate_limited", "", requestID)
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
	}

	beforeHash := shortHash(body.YAML)
	result, err := s.resources.Apply(r.Context(), gvr, namespace, name, []byte(body.YAML), body.DryRun)
	if err != nil {
		outcome := "failed"
		if !body.DryRun {
			// log + audit — dry-run failures are visible to the user already.
			slog.ErrorContext(r.Context(), resource+".apply.failed",
				slog.String("user", user.Username),
				slog.String("namespace", namespace),
				slog.String("name", name),
				slog.Any("error", err),
				slog.String("request_id", requestID),
			)
		}
		s.recordApplyAudit(user.Username, namespace, name, resource, outcome,
			fmt.Sprintf("dry=%v from=%s err=%s", body.DryRun, beforeHash, err.Error()), requestID)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	afterHash := shortHash(result.AppliedYAML)
	outcome := "success"
	details := fmt.Sprintf("dry=%v from=%s to=%s", body.DryRun, beforeHash, afterHash)
	s.recordApplyAudit(user.Username, namespace, name, resource, outcome, details, requestID)

	writeJSON(w, http.StatusOK, map[string]any{
		"applied": result.AppliedYAML,
		"dryRun":  result.DryRun,
	})
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func (s *Server) recordApplyAudit(user, namespace, name, resource, outcome, details, requestID string) {
	resourceName := name
	if details != "" {
		resourceName = fmt.Sprintf("%s (%s)", name, details)
	}
	go s.audit.Record(context.Background(), models.AuditLog{
		User:         user,
		Action:       resource + ".apply." + outcome,
		Namespace:    namespace,
		ResourceType: resource,
		ResourceName: resourceName,
	})
	slog.Info("yaml.apply",
		slog.String("resource", resource),
		slog.String("outcome", outcome),
		slog.String("user", user),
		slog.String("namespace", namespace),
		slog.String("name", name),
		slog.String("details", details),
		slog.String("request_id", requestID),
	)
}
