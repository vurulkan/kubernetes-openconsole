package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

// maxReplicas caps the replica count a client may request via the Scale endpoint.
// Guards against accidental runaway scaling; override with MAX_REPLICAS env.
const defaultMaxReplicas = 100

// allowDeployAction is a per-user token bucket limiting write actions:
// burst 5, refill 10/min.
func (s *Server) allowDeployAction(userID int) bool {
	s.deployLimitersMu.Lock()
	defer s.deployLimitersMu.Unlock()
	limiter, ok := s.deployLimiters[userID]
	if !ok {
		limiter = rate.NewLimiter(rate.Every(6*time.Second), 5)
		s.deployLimiters[userID] = limiter
	}
	return limiter.Allow()
}

// handleDeploymentRestart issues a rolling restart on a Deployment.
// Requires permission deployments:restart; records audit (success/denied/failed).
func (s *Server) handleDeploymentRestart(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	if !s.can(r.Context(), user.ID, namespace, "deployments", "restart") {
		reason := s.denyReason(r.Context(), namespace, "deployments", "restart")
		s.recordDeployAudit(r, namespace, name, audit.VerbRestart, audit.Denied, reason, nil)
		writeError(w, http.StatusForbidden, reason)
		return
	}

	if !s.allowDeployAction(user.ID) {
		w.Header().Set("Retry-After", "6")
		s.recordDeployAudit(r, namespace, name, audit.VerbRestart, audit.RateLimited, reasonRateLimited, nil)
		writeError(w, http.StatusTooManyRequests, problem.RateLimited)
		return
	}

	MetricsDeployAction()
	stamp, err := s.resources.RestartDeployment(r.Context(), namespace, name)
	if err != nil {
		s.recordDeployAudit(r, namespace, name, audit.VerbRestart, audit.Failed, failReason(err), failDetails(err, nil))
		writeActionError(w, err, "restart failed")
		return
	}

	s.recordDeployAudit(r, namespace, name, audit.VerbRestart, audit.Success, "", audit.D{"restarted_at": stamp})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"restartedAt": stamp,
	})
}

// handleDeploymentScale updates replica count. Body: {"replicas": <int>}
func (s *Server) handleDeploymentScale(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	if !s.can(r.Context(), user.ID, namespace, "deployments", "scale") {
		reason := s.denyReason(r.Context(), namespace, "deployments", "scale")
		s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.Denied, reason, nil)
		writeError(w, http.StatusForbidden, reason)
		return
	}

	var body struct {
		Replicas int32 `json:"replicas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.Failed, reasonInvalid, nil)
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	max := int32(defaultMaxReplicas)
	if v := strings.TrimSpace(os.Getenv("MAX_REPLICAS")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			max = int32(parsed)
		}
	}
	if body.Replicas < 0 || body.Replicas > max {
		s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.Failed, reasonInvalid, audit.D{"replicas_to": body.Replicas})
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, fmt.Sprintf("replicas must be between 0 and %d", max))
		return
	}

	if !s.allowDeployAction(user.ID) {
		w.Header().Set("Retry-After", "6")
		s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.RateLimited, reasonRateLimited, audit.D{"replicas_to": body.Replicas})
		writeError(w, http.StatusTooManyRequests, problem.RateLimited)
		return
	}

	MetricsDeployAction()
	previous, err := s.resources.ScaleDeployment(r.Context(), namespace, name, body.Replicas)
	if err != nil {
		s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.Failed, failReason(err),
			failDetails(err, audit.D{"replicas_from": previous, "replicas_to": body.Replicas}))
		writeActionError(w, err, "scale failed")
		return
	}

	s.recordDeployAudit(r, namespace, name, audit.VerbScale, audit.Success, "",
		audit.D{"replicas_from": previous, "replicas_to": body.Replicas})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"previous": previous,
		"replicas": body.Replicas,
	})
}

func (s *Server) recordDeployAudit(r *http.Request, namespace, name, verb, outcome, reason string, details audit.D) {
	s.auditEvent(r, models.AuditLog{
		Verb:         verb,
		Outcome:      outcome,
		Reason:       reason,
		ResourceType: "deployment",
		Namespace:    namespace,
		ResourceName: name,
		Details:      details,
	})
}

// writeActionError reports a failed write action. Kubernetes API errors keep
// their real status — notably 403 when the ServiceAccount's ClusterRole does
// not allow the verb (e.g. the read-only RBAC) — with the server's message;
// anything else (cluster unreachable) stays a 502.
func writeActionError(w http.ResponseWriter, err error, fallback string) {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		st := httpStatusFor(err)
		writeErrorDetail(w, st, kubeWriteCode(st), fallback+": "+err.Error())
		return
	}
	writeErrorDetail(w, http.StatusBadGateway, problem.ClusterUnreachable, fallback)
}
