package api

import (
	"bufio"
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// handleDeploymentLogsWS fans out `kubectl logs -f -l <selector> --all-containers --prefix`
// style streaming. It discovers the deployment's pods via its labelSelector,
// opens a log stream per (pod, container), prefixes each line with
// `[pod/container] ` and multiplexes them onto a single WebSocket.
//
// RBAC: caller needs deployments:get AND pods:logs on the namespace.
func (s *Server) handleDeploymentLogsWS(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	deploymentName := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), claims.UserID, namespace, "deployments", "get") ||
		!s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.allowLogStream(claims.UserID) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	client, ok := kubeFor(r).Client()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Resolve pods via the deployment's label selector. Deployments always
	// carry one (API server rejects otherwise) so there is no "no label"
	// edge case to worry about.
	deploy, err := client.AppsV1().Deployments(namespace).Get(r.Context(), deploymentName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "deployment not found")
		return
	}
	selector := metav1.FormatLabelSelector(deploy.Spec.Selector)
	podList, err := client.CoreV1().Pods(namespace).List(r.Context(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "failed to list pods: "+err.Error())
		return
	}
	if len(podList.Items) == 0 {
		writeError(w, http.StatusNotFound, "no pods match deployment selector")
		return
	}

	tail := int64(100)
	if v := r.URL.Query().Get("tail"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			tail = parsed
		}
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("deployment logs ws upgrade failed", slog.Any("error", err))
		return
	}
	defer conn.Close()

	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         claims.Username,
		Action:       "deployment.logs",
		Namespace:    namespace,
		ResourceType: "deployment",
		ResourceName: deploymentName,
	})
	slog.Info("deployment.logs.start",
		slog.String("user", claims.Username),
		slog.String("namespace", namespace),
		slog.String("deployment", deploymentName),
		slog.Int("pods", len(podList.Items)),
		slog.String("request_id", requestID),
	)

	// writeMu serializes WS writes from the fan-in goroutines.
	var writeMu sync.Mutex
	writeLine := func(prefix, line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		msg := "[" + prefix + "] " + line + "\n"
		_ = conn.WriteMessage(websocket.TextMessage, []byte(msg))
	}
	writeMeta := func(line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(line+"\n"))
	}

	// A single cancel propagates to every per-container goroutine when either
	// the client disconnects or any stream errors terminally.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Watch for client-initiated close so we can tear down all streams.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	writeMeta("[openconsole] streaming " + strconv.Itoa(len(podList.Items)) + " pod(s) for " + deploymentName)

	for _, pod := range podList.Items {
		podName := pod.Name
		for _, container := range pod.Spec.Containers {
			containerName := container.Name
			wg.Add(1)
			go func() {
				defer wg.Done()
				opts := &corev1.PodLogOptions{
					Container: containerName,
					Follow:    true,
					TailLines: &tail,
				}
				stream, err := client.CoreV1().Pods(namespace).GetLogs(podName, opts).Stream(ctx)
				if err != nil {
					writeMeta("[openconsole] " + podName + "/" + containerName + " error: " + err.Error())
					return
				}
				defer stream.Close()
				scanner := bufio.NewScanner(stream)
				// Allow larger log lines than scanner's default 64KB.
				scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
				prefix := podName + "/" + containerName
				for scanner.Scan() {
					if ctx.Err() != nil {
						return
					}
					writeLine(prefix, strings.TrimRight(scanner.Text(), "\r\n"))
				}
				if err := scanner.Err(); err != nil && ctx.Err() == nil {
					writeMeta("[openconsole] " + prefix + " stream ended: " + err.Error())
				}
			}()
		}
	}

	// Block until all streams drain (follow=true means they drain only on cancel/close).
	wg.Wait()
}
