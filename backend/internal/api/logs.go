package api

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
)

// Log sockets speak JSON frames, so status never mixes with log text:
//
//	{"t":"line","ts":"…","p":"pod","c":"container","text":"…"}
//	{"t":"end","reason":"previous_complete|container_terminated|pod_deleted|interrupted","retry":bool}
//	{"t":"error","reason":"forbidden|rate_limited|not_ready|container_not_found|previous_unavailable|no_pods|unavailable","retry":bool}
//
// retry tells the viewer to reconnect with ?sinceTime=<last ts>&skip=<lines at that ts>&resume=true.
// An error frame with "p" set is about one stream of a multi-pod view; the others go on.
type logFrame struct {
	T      string `json:"t"`
	TS     string `json:"ts,omitempty"`
	Pod    string `json:"p,omitempty"`
	C      string `json:"c,omitempty"`
	Text   string `json:"text,omitempty"`
	Reason string `json:"reason,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Retry  bool   `json:"retry,omitempty"`
}

// Fixed width, so the browser can compare timestamps as strings.
const logTSLayout = "2006-01-02T15:04:05.000000000Z"

// resumeFilter drops lines the viewer already has. Kubernetes' sinceTime has one-second
// precision, so a resumed stream starts at the second of the last line seen: lines before
// it, and the first skip lines exactly at it, are repeats.
type resumeFilter struct {
	since time.Time
	skip  int
}

func (f *resumeFilter) keep(ts time.Time) bool {
	if f.since.IsZero() || ts.After(f.since) {
		return true
	}
	if ts.Equal(f.since) && f.skip > 0 {
		f.skip--
		return false
	}
	return ts.Equal(f.since)
}

func parseResume(r *http.Request) resumeFilter {
	q := r.URL.Query()
	since, err := time.Parse(time.RFC3339Nano, q.Get("sinceTime"))
	if err != nil {
		return resumeFilter{}
	}
	skip, _ := strconv.Atoi(q.Get("skip"))
	return resumeFilter{since: since, skip: skip}
}

func logTail(r *http.Request) int64 {
	if parsed, err := strconv.ParseInt(r.URL.Query().Get("tail"), 10, 64); err == nil && parsed > 0 {
		return parsed
	}
	return 100
}

// logErrorReason maps a failed GetLogs to a frame reason; not_ready is worth retrying on a live view.
func logErrorReason(err error, previous bool) string {
	msg := err.Error()
	switch {
	case apierrors.IsForbidden(err):
		return "forbidden"
	case strings.Contains(msg, "is not valid for pod"):
		return "container_not_found"
	case previous && (apierrors.IsBadRequest(err) || apierrors.IsNotFound(err)):
		return "previous_unavailable"
	case apierrors.IsNotFound(err):
		return "pod_deleted"
	case apierrors.IsBadRequest(err): // "is waiting to start", "ContainerCreating"
		return "not_ready"
	}
	return "unavailable"
}

// wsFail answers a refused log socket. A browser cannot read the HTTP status of a failed
// upgrade, so a WebSocket client gets the reason as an error frame; plain HTTP gets the status.
func wsFail(w http.ResponseWriter, r *http.Request, status int, reason string) {
	if !websocket.IsWebSocketUpgrade(r) {
		w.WriteHeader(status)
		return
	}
	conn, err := logUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.WriteJSON(logFrame{T: "error", Reason: reason, Retry: reason == "rate_limited"})
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

var logUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// logSocket serializes writes from the per-stream goroutines.
type logSocket struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (s *logSocket) send(f logFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.WriteJSON(f)
}

func (s *logSocket) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// pump reads a timestamped log stream into line frames until it ends. With timestamps on,
// every container line starts with one; a line without it is the kubelet talking ("unable to
// retrieve container logs for …" once a log was rotated away), so it comes back as a note
// for the status bar instead of going into the log.
func pump(ctx context.Context, stream io.Reader, pod, container string, filter resumeFilter, send func(logFrame)) (note string) {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() && ctx.Err() == nil {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		raw, text, _ := strings.Cut(line, " ")
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			if note == "" {
				note = line
			}
			continue
		}
		if filter.keep(ts) {
			send(logFrame{T: "line", TS: ts.UTC().Format(logTSLayout), Pod: pod, C: container, Text: text})
		}
	}
	return note
}

// readerContext cancels when the client closes the socket, so the Kubernetes streams end with it.
func readerContext(parent context.Context, conn *websocket.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()
	return ctx, cancel
}

func (s *Server) handlePodLogsWS(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	podName := chi.URLParam(r, "name")
	q := r.URL.Query()
	previous := q.Get("previous") == "true"
	container := q.Get("container")
	podLogs := models.AuditLog{
		Verb:         audit.VerbLogs,
		ResourceType: "pod",
		Namespace:    namespace,
		ResourceName: podName,
		Details:      audit.D{"container": container},
	}
	if previous {
		podLogs.Details["previous"] = true
	}
	if !s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		podLogs.Outcome, podLogs.Reason = audit.Denied, reasonForbidden
		s.auditEvent(r, podLogs)
		wsFail(w, r, http.StatusForbidden, "forbidden")
		return
	}
	if !s.allowLogStream(claims.UserID) {
		podLogs.Outcome, podLogs.Reason = audit.RateLimited, reasonRateLimited
		s.auditEvent(r, podLogs)
		wsFail(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	client, ok := kubeFor(r).Client()
	if !ok {
		wsFail(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	pod, podErr := client.CoreV1().Pods(namespace).Get(r.Context(), podName, metav1.GetOptions{})
	if container == "" && podErr == nil {
		// Kubernetes refuses a log request without a container when the pod has several.
		container = defaultContainer(pod)
		podLogs.Details["container"] = container
	}
	// Reconnects after a drop are the same viewing session: audited once, when opened.
	if q.Get("resume") != "true" {
		s.auditEvent(r, podLogs)
	}

	conn, err := logUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logWarnf("logs ws upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	MetricsLogStreamIncr()
	sock := &logSocket{conn: conn}
	defer sock.close()
	ctx, cancel := readerContext(r.Context(), conn)
	defer cancel()

	opts := models.PodLogOptions{Container: container, TailLines: logTail(r), Previous: previous}
	filter := parseResume(r)
	if !filter.since.IsZero() {
		opts.SinceTime = filter.since.Truncate(time.Second)
	}
	stream, err := client.CoreV1().Pods(namespace).GetLogs(podName, opts.ToKube()).Stream(ctx)
	if err != nil {
		reason := logErrorReason(err, previous)
		sock.send(logFrame{T: "error", Reason: reason, Msg: err.Error(), Retry: reason == "not_ready" && !previous})
		return
	}
	note := pump(ctx, stream, "", container, filter, sock.send)
	stream.Close()
	if ctx.Err() != nil {
		return
	}
	if previous {
		if note != "" {
			sock.send(logFrame{T: "error", Reason: "previous_unavailable", Msg: note})
		} else {
			sock.send(logFrame{T: "end", Reason: "previous_complete"})
		}
		return
	}
	end := liveLogEnd(ctx, client, namespace, podName, container, restartsOf(pod, container))
	end.Msg = note
	sock.send(end)
}

// liveLogEnd explains why a followed log stopped: the container exited (and will it come
// back?), the pod is gone, or the connection was cut while the container still runs.
func liveLogEnd(ctx context.Context, client kubernetes.Interface, namespace, podName, container string, restartsBefore int32) logFrame {
	pod, err := client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return logFrame{T: "end", Reason: "pod_deleted"}
	}
	if err != nil {
		return logFrame{T: "end", Reason: "interrupted", Retry: true}
	}
	cs := containerStatus(pod, container)
	if cs != nil && cs.State.Running != nil && cs.RestartCount == restartsBefore {
		return logFrame{T: "end", Reason: "interrupted", Retry: true}
	}
	return logFrame{T: "end", Reason: "container_terminated", Retry: willRestart(pod, cs)}
}

func willRestart(pod *corev1.Pod, cs *corev1.ContainerStatus) bool {
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return false
	}
	if cs == nil || cs.State.Terminated == nil || cs.State.Terminated.ExitCode != 0 {
		return true // running again, waiting to restart, or failed
	}
	// A clean exit restarts only under restartPolicy Always, and never for an init container.
	for _, c := range pod.Spec.InitContainers {
		if c.Name == cs.Name {
			return false
		}
	}
	return pod.Spec.RestartPolicy == "" || pod.Spec.RestartPolicy == corev1.RestartPolicyAlways
}

func containerStatus(pod *corev1.Pod, container string) *corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	for _, list := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses} {
		for i := range list {
			if list[i].Name == container {
				return &list[i]
			}
		}
	}
	return nil
}

func restartsOf(pod *corev1.Pod, container string) int32 {
	if cs := containerStatus(pod, container); cs != nil {
		return cs.RestartCount
	}
	return 0
}

// defaultContainer picks the container kubectl would: the one named by the
// kubectl.kubernetes.io/default-container annotation, else the first.
func defaultContainer(pod *corev1.Pod) string {
	if name := pod.Annotations["kubectl.kubernetes.io/default-container"]; name != "" {
		for _, c := range pod.Spec.Containers {
			if c.Name == name {
				return name
			}
		}
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name
	}
	return ""
}

// handleDeploymentLogsWS follows every pod × container of a deployment, like
// `kubectl logs -f -l <selector> --all-containers --prefix`.
// RBAC: deployments:get AND pods:logs.
func (s *Server) handleDeploymentLogsWS(w http.ResponseWriter, r *http.Request) {
	s.workloadLogsWS(w, r, "deployment", "deployments", func(ctx context.Context, client kubernetes.Interface, namespace, name string) ([]corev1.Pod, error) {
		deploy, err := client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		list, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(deploy.Spec.Selector)})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

// handleJobLogsWS is the same for a Job: its pods carry job-name=<job> (set by the Job controller).
// RBAC: jobs:get AND pods:logs.
func (s *Server) handleJobLogsWS(w http.ResponseWriter, r *http.Request) {
	s.workloadLogsWS(w, r, "job", "jobs", func(ctx context.Context, client kubernetes.Interface, namespace, name string) ([]corev1.Pod, error) {
		list, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + name})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

type podLister func(ctx context.Context, client kubernetes.Interface, namespace, name string) ([]corev1.Pod, error)

func (s *Server) workloadLogsWS(w http.ResponseWriter, r *http.Request, kind, resource string, listPods podLister) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	logsEvent := models.AuditLog{Verb: audit.VerbLogs, ResourceType: kind, Namespace: namespace, ResourceName: name}
	if !s.can(r.Context(), claims.UserID, namespace, resource, "get") ||
		!s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		logsEvent.Outcome, logsEvent.Reason = audit.Denied, reasonForbidden
		s.auditEvent(r, logsEvent)
		wsFail(w, r, http.StatusForbidden, "forbidden")
		return
	}
	if !s.allowLogStream(claims.UserID) {
		logsEvent.Outcome, logsEvent.Reason = audit.RateLimited, reasonRateLimited
		s.auditEvent(r, logsEvent)
		wsFail(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	client, ok := kubeFor(r).Client()
	if !ok {
		wsFail(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	pods, err := listPods(r.Context(), client, namespace, name)
	if err != nil {
		wsFail(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if len(pods) == 0 {
		wsFail(w, r, http.StatusNotFound, "no_pods")
		return
	}

	conn, err := logUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn(kind+" logs ws upgrade failed", slog.Any("error", err))
		return
	}
	defer conn.Close()
	MetricsLogStreamIncr()
	if r.URL.Query().Get("resume") != "true" {
		logsEvent.Details = audit.D{"pods": len(pods)}
		s.auditEvent(r, logsEvent)
	}
	sock := &logSocket{conn: conn}
	defer sock.close()
	ctx, cancel := readerContext(r.Context(), conn)
	defer cancel()

	tail := logTail(r)
	// shortcut: one sinceTime for all pods, so a line another pod wrote just before the
	// drop but had not delivered yet is lost; per-pod resume points if that ever matters.
	filter := parseResume(r)
	var wg sync.WaitGroup
	for _, pod := range pods {
		for _, c := range pod.Spec.Containers {
			podName, container := pod.Name, c.Name
			wg.Add(1)
			go func() {
				defer wg.Done()
				opts := models.PodLogOptions{Container: container, TailLines: tail}
				if !filter.since.IsZero() {
					opts.SinceTime = filter.since.Truncate(time.Second)
				}
				stream, err := client.CoreV1().Pods(namespace).GetLogs(podName, opts.ToKube()).Stream(ctx)
				if err != nil {
					sock.send(logFrame{T: "error", Pod: podName, C: container, Reason: logErrorReason(err, false), Msg: err.Error()})
					return
				}
				defer stream.Close()
				if note := pump(ctx, stream, podName, container, filter, sock.send); note != "" {
					sock.send(logFrame{T: "error", Pod: podName, C: container, Reason: "unavailable", Msg: note})
				}
			}()
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	// Every stream ended: worth following again only while some pod still runs (a rollout,
	// a cut connection). A finished Job is done.
	end := logFrame{T: "end", Reason: "container_terminated"}
	if now, err := listPods(ctx, client, namespace, name); err == nil {
		for _, p := range now {
			if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
				end.Reason, end.Retry = "interrupted", true
				break
			}
		}
	}
	sock.send(end)
}
