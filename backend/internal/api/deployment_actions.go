package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// maxReplicas caps the replica count a client may request via the Scale endpoint.
// Guards against accidental runaway scaling; override with MAX_REPLICAS env.
const defaultMaxReplicas = 100

// deployActionsLimiter is a per-user token bucket limiting write actions.
// Burst 5, refill 10/min. Reset in tests via resetDeployActionLimiters.
var (
	deployActionsLimiters   = map[int]*rate.Limiter{}
	deployActionsLimitersMu = sync.Mutex{}
)

func allowDeployAction(userID int) bool {
	deployActionsLimitersMu.Lock()
	defer deployActionsLimitersMu.Unlock()
	limiter, ok := deployActionsLimiters[userID]
	if !ok {
		limiter = rate.NewLimiter(rate.Every(6*time.Second), 5)
		deployActionsLimiters[userID] = limiter
	}
	return limiter.Allow()
}

// handleDeploymentRestart issues a rolling restart on a Deployment.
// Requires permission deployments:restart; records audit (success/denied/failed).
func (s *Server) handleDeploymentRestart(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), user.ID, namespace, "deployments", "restart") {
		s.recordDeployAudit(user.Username, namespace, name, "deployment.restart", "denied", "", requestID)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if !allowDeployAction(user.ID) {
		w.Header().Set("Retry-After", "6")
		s.recordDeployAudit(user.Username, namespace, name, "deployment.restart", "rate_limited", "", requestID)
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	stamp, err := s.resources.RestartDeployment(r.Context(), namespace, name)
	if err != nil {
		slog.ErrorContext(r.Context(), "deployment.restart.failed",
			slog.String("user", user.Username),
			slog.String("namespace", namespace),
			slog.String("deployment", name),
			slog.Any("error", err),
			slog.String("request_id", requestID),
		)
		s.recordDeployAudit(user.Username, namespace, name, "deployment.restart", "failed", err.Error(), requestID)
		writeError(w, http.StatusBadGateway, "restart failed")
		return
	}

	s.recordDeployAudit(user.Username, namespace, name, "deployment.restart", "success", "restartedAt="+stamp, requestID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"restartedAt": stamp,
	})
}

// handleDeploymentScale updates replica count. Body: {"replicas": <int>}
func (s *Server) handleDeploymentScale(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), user.ID, namespace, "deployments", "scale") {
		s.recordDeployAudit(user.Username, namespace, name, "deployment.scale", "denied", "", requestID)
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
		s.recordDeployAudit(user.Username, namespace, name, "deployment.scale", "rate_limited", "", requestID)
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	previous, err := s.resources.ScaleDeployment(r.Context(), namespace, name, body.Replicas)
	if err != nil {
		slog.ErrorContext(r.Context(), "deployment.scale.failed",
			slog.String("user", user.Username),
			slog.String("namespace", namespace),
			slog.String("deployment", name),
			slog.Int("target_replicas", int(body.Replicas)),
			slog.Any("error", err),
			slog.String("request_id", requestID),
		)
		s.recordDeployAudit(user.Username, namespace, name, "deployment.scale", "failed",
			fmt.Sprintf("from=%d to=%d err=%s", previous, body.Replicas, err.Error()), requestID)
		writeError(w, http.StatusBadGateway, "scale failed")
		return
	}

	s.recordDeployAudit(user.Username, namespace, name, "deployment.scale", "success",
		fmt.Sprintf("from=%d to=%d", previous, body.Replicas), requestID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"previous": previous,
		"replicas": body.Replicas,
	})
}

func (s *Server) recordDeployAudit(user, namespace, name, action, outcome, details, requestID string) {
	resourceName := name
	if details != "" {
		resourceName = fmt.Sprintf("%s (%s)", name, details)
	}
	go s.audit.Record(s.auditCtxFromID(requestID), models.AuditLog{
		User:         user,
		Action:       action + "." + outcome,
		Namespace:    namespace,
		ResourceType: "deployment",
		ResourceName: resourceName,
	})
	slog.Info("deployment.action",
		slog.String("event", action),
		slog.String("outcome", outcome),
		slog.String("user", user),
		slog.String("namespace", namespace),
		slog.String("deployment", name),
		slog.String("details", details),
		slog.String("request_id", requestID),
	)
}
