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

// handleJobLogsWS mirrors handleDeploymentLogsWS for a batchv1 Job. Pods
// managed by a Job always carry the `job-name=<jobName>` label (set by the
// Job controller), so we discover their logs via that label selector rather
// than parsing ownerReferences. Behavior is otherwise identical: one WS,
// one goroutine per (pod × container), each line prefixed [pod/container].
//
// RBAC: caller needs jobs:get AND pods:logs on the namespace.
func (s *Server) handleJobLogsWS(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	jobName := chi.URLParam(r, "name")
	requestID := logging.RequestIDFrom(r.Context())

	if !s.can(r.Context(), claims.UserID, namespace, "jobs", "get") ||
		!s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.allowLogStream(claims.UserID) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	client, ok := s.kube.Client()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	podList, err := client.CoreV1().Pods(namespace).List(r.Context(), metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "failed to list pods: "+err.Error())
		return
	}
	if len(podList.Items) == 0 {
		writeError(w, http.StatusNotFound, "no pods found for this job")
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
		slog.Warn("job logs ws upgrade failed", slog.Any("error", err))
		return
	}
	defer conn.Close()

	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         claims.Username,
		Action:       "job.logs",
		Namespace:    namespace,
		ResourceType: "job",
		ResourceName: jobName,
	})
	slog.Info("job.logs.start",
		slog.String("user", claims.Username),
		slog.String("namespace", namespace),
		slog.String("job", jobName),
		slog.Int("pods", len(podList.Items)),
		slog.String("request_id", requestID),
	)

	var writeMu sync.Mutex
	writeLine := func(prefix, line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("["+prefix+"] "+line+"\n"))
	}
	writeMeta := func(line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(line+"\n"))
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	writeMeta("[openconsole] streaming " + strconv.Itoa(len(podList.Items)) + " pod(s) for job " + jobName)

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

	wg.Wait()
}
