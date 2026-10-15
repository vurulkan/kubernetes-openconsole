package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
)

// resourceTarget maps the URL segment to both the GVR (needed by the dynamic
// client) and the Kind (needed when the YAML body is missing apiVersion/kind
// and we have to fill it in). Keeping them together removes the common bug
// where a Dashboard upgrade only remembered to update one of two tables.
type resourceTarget struct {
	GVR  schema.GroupVersionResource
	Kind string
}

var resourceGVR = map[string]resourceTarget{
	"pods":         {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, "Pod"},
	"services":     {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, "Service"},
	"configmaps":   {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "ConfigMap"},
	"secrets":      {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, "Secret"},
	"deployments":  {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "Deployment"},
	"daemonsets":   {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, "DaemonSet"},
	"statefulsets": {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, "StatefulSet"},
	"hpas":         {schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, "HorizontalPodAutoscaler"},
	"ingresses":    {schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, "Ingress"},
	"cronjobs":     {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, "CronJob"},
	"jobs":         {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, "Job"},
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
// Audit: <kind>.apply, outcome success / denied / rate_limited / failed,
//
//	with dry_run and the yaml_from / yaml_to sha256 hashes as details.
//	Hashes rather than full bodies keep the audit table small and
//	non-leaky.
func (s *Server) handleYAMLApply(w http.ResponseWriter, r *http.Request) {
	resource := chi.URLParam(r, "resource")
	target, ok := resourceGVR[resource]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported resource type")
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !s.can(r.Context(), user.ID, namespace, resource, "edit") {
		s.recordApplyAudit(r, namespace, name, resource, audit.Denied, reasonForbidden, nil)
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
			s.recordApplyAudit(r, namespace, name, resource, audit.RateLimited, reasonRateLimited, audit.D{"dry_run": false})
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
	}

	beforeHash := shortHash(body.YAML)
	result, err := s.resources.Apply(r.Context(), target.GVR, target.Kind, namespace, name, []byte(body.YAML), body.DryRun)
	if err != nil {
		s.recordApplyAudit(r, namespace, name, resource, audit.Failed, failReason(err),
			failDetails(err, audit.D{"dry_run": body.DryRun, "yaml_from": beforeHash}))

		// Map k8s API errors to the right HTTP status so a reverse proxy
		// (Cloudflare, ingress-nginx) doesn't intercept a 5xx and show its
		// own branded page for what is actually a user mistake (bad YAML,
		// stale resourceVersion, missing field, etc.).
		writeError(w, httpStatusFor(err), err.Error())
		return
	}

	afterHash := shortHash(result.AppliedYAML)
	s.recordApplyAudit(r, namespace, name, resource, audit.Success, "",
		audit.D{"dry_run": body.DryRun, "yaml_from": beforeHash, "yaml_to": afterHash})

	writeJSON(w, http.StatusOK, map[string]any{
		"applied": result.AppliedYAML,
		"dryRun":  result.DryRun,
	})
}

// httpStatusFor turns a k8s apierror (or a client-side validation we raised)
// into the matching HTTP status. Anything we can't classify falls through to
// 422 Unprocessable Entity so the browser receives a 4xx — Cloudflare and
// friends happily pass that through as-is instead of overlaying their 5xx
// error page.
func httpStatusFor(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case apierrors.IsNotFound(err):
		return http.StatusNotFound
	case apierrors.IsConflict(err):
		return http.StatusConflict
	case apierrors.IsForbidden(err):
		return http.StatusForbidden
	case apierrors.IsUnauthorized(err):
		return http.StatusUnauthorized
	case apierrors.IsAlreadyExists(err):
		return http.StatusConflict
	case apierrors.IsInvalid(err),
		apierrors.IsBadRequest(err),
		apierrors.IsRequestEntityTooLargeError(err):
		return http.StatusBadRequest
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return http.StatusGatewayTimeout
	case apierrors.IsServiceUnavailable(err):
		return http.StatusServiceUnavailable
	case apierrors.IsInternalError(err):
		return http.StatusInternalServerError
	}
	// Our own guardrails (name/namespace mismatch, missing resourceVersion,
	// YAML parse error) all land here. They're all client-side problems.
	return http.StatusUnprocessableEntity
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func (s *Server) recordApplyAudit(r *http.Request, namespace, name, resource, outcome, reason string, details audit.D) {
	s.auditEvent(r, models.AuditLog{
		Verb:         audit.VerbApply,
		Outcome:      outcome,
		Reason:       reason,
		ResourceType: audit.Kind(resource),
		Namespace:    namespace,
		ResourceName: name,
		Details:      details,
	})
}
