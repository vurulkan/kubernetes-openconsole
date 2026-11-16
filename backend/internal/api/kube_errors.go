package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/problem"
)

// Reason codes of a read the cluster answered with an error (the body's "error").
const (
	reasonClusterForbidden   = problem.ClusterForbidden   // the cluster credentials may not read this (ClusterRole)
	reasonClusterTimeout     = problem.ClusterTimeout     // the API server didn't answer in time
	reasonClusterUnreachable = problem.ClusterUnreachable // no answer at all, or the cluster refused the credentials
	reasonNotConnected       = problem.NotConnected       // no connection to the cluster
	reasonNotFound           = problem.NotFound
)

// kubeReadError maps an error from reading the cluster to a status and a
// reason code (other API errors keep their status and message).
func kubeReadError(err error) (int, string) {
	var netErr net.Error
	var status apierrors.APIStatus
	switch {
	case errors.Is(err, kube.ErrNotReady):
		return http.StatusServiceUnavailable, reasonNotConnected
	case apierrors.IsForbidden(err):
		return http.StatusForbidden, reasonClusterForbidden
	case apierrors.IsNotFound(err):
		return http.StatusNotFound, reasonNotFound
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return http.StatusGatewayTimeout, reasonClusterTimeout
	case apierrors.IsUnauthorized(err):
		// Not 401: that would read as "your session ended" and sign the user out.
		return http.StatusBadGateway, reasonClusterUnreachable
	case errors.As(err, &status):
		return httpStatusFor(err), err.Error()
	}
	return http.StatusBadGateway, reasonClusterUnreachable
}

// writeReadError answers a read of resource that the cluster failed with
// the real reason instead of an empty list or a bare 404 / 503, and logs it
// with the request id: a missing ClusterRole rule must not look like "nothing
// here". Reads are audited only when they succeed or are denied by
// OpenConsole's own permissions; this is neither.
func writeReadError(w http.ResponseWriter, r *http.Request, err error, resource string) {
	code, reason := kubeReadError(err)
	level := slog.LevelWarn
	if code == http.StatusNotFound {
		level = slog.LevelDebug
	}
	slog.Log(r.Context(), level, "cluster read failed",
		slog.String("resource", resource),
		slog.Int("status", code),
		slog.String("reason", reason),
		slog.String("cluster", logpkg.ClusterFrom(r.Context())),
		slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
		slog.Any("error", err),
	)
	writeError(w, code, reason)
}

// kubeWriteCode is the reason code for a write the cluster refused, by the
// status httpStatusFor gave it.
func kubeWriteCode(status int) string {
	switch status {
	case http.StatusForbidden:
		return problem.ClusterForbidden
	case http.StatusNotFound:
		return problem.NotFound
	case http.StatusConflict:
		return problem.Conflict
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return problem.InvalidInput
	case http.StatusBadGateway:
		return problem.ClusterUnreachable
	case http.StatusGatewayTimeout:
		return problem.ClusterTimeout
	}
	return problem.ClusterError
}
