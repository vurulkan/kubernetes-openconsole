package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// Limits of POST /api/namespaces/{namespace}/pods/{name}/exec (M16).
const (
	execCommandMaxOutput      = 1 << 20 // bytes kept per stream (stdout, stderr)
	execCommandDefaultTimeout = 30
	execCommandMaxTimeout     = 120
)

// execCommandRequest is the body: argv (never wrapped in a shell), container, timeout.
type execCommandRequest struct {
	Container      string   `json:"container"`
	Command        []string `json:"command"`
	TimeoutSeconds *int     `json:"timeoutSeconds"`
}

type execCommandResponse struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exitCode"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"durationMs"`
}

// streamPodCommand runs argv in a container: stdout and stderr, no stdin, no TTY.
// A variable so tests can stand in for the API server (the fake clientset has no exec).
var streamPodCommand = func(ctx context.Context, m *kube.Manager, namespace, pod, container string, argv []string, stdout, stderr io.Writer) error {
	client, ok := m.Client()
	cfg, ok2 := m.RESTConfig()
	if !ok || !ok2 {
		return errNotConnected
	}
	req := client.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: container, Command: argv, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return err
	}
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: stdout, Stderr: stderr})
}

// capped keeps the first execCommandMaxOutput bytes of a stream and counts the rest,
// so a command that prints too much still runs to its end and reports its exit code.
// Locked: on a timeout client-go may still be copying when StreamWithContext returns.
type capped struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	total int64
	tee   func([]byte) // the recording
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += int64(len(p))
	if room := execCommandMaxOutput - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	c.tee(p)
	return len(p), nil
}

// result returns the kept output, the bytes seen and whether some were dropped.
func (c *capped) result() (string, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String(), c.total, c.total > int64(c.buf.Len())
}

// handlePodExecCommand runs one command in a pod and returns its output (M16): for agents
// and scripts, which shouldn't need a WebSocket. Same permission (pods:exec), feature flag,
// shell limit and recorder as the shell; the full command is in the recording only, never
// in the audit log or the console log (it may carry a password).
func (s *Server) handlePodExecCommand(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace, podName := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	details := audit.D{"mode": models.RecordingModeCommand}
	refuse := func(status int, outcome, reason string) {
		s.recordExecAudit(r, namespace, podName, outcome, reason, details)
		writeError(w, status, reason)
	}

	if !featureAllows("pods", "exec") {
		refuse(http.StatusForbidden, audit.Denied, reasonFeatureDisabled)
		return
	}
	if !s.can(r.Context(), claims.UserID, namespace, "pods", "exec") {
		refuse(http.StatusForbidden, audit.Denied, s.denyReason(r.Context(), namespace, "pods", "exec"))
		return
	}

	var req execCommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "the body must be JSON: {\"command\": [\"cat\", \"/etc/os-release\"], \"container\": \"…\", \"timeoutSeconds\": 30}")
		return
	}
	if len(req.Command) == 0 || strings.TrimSpace(req.Command[0]) == "" {
		writeError(w, http.StatusBadRequest, "command must be a non-empty array, e.g. [\"cat\", \"/etc/os-release\"]; it is not run in a shell")
		return
	}
	details["program"] = req.Command[0]
	timeout := execCommandDefaultTimeout
	if req.TimeoutSeconds != nil {
		timeout = *req.TimeoutSeconds
	}
	if timeout < 1 || timeout > execCommandMaxTimeout {
		writeError(w, http.StatusBadRequest, "timeoutSeconds must be between 1 and "+strconv.Itoa(execCommandMaxTimeout))
		return
	}

	client, ok := kubeFor(r).Client()
	if !ok {
		refuse(http.StatusServiceUnavailable, audit.Failed, "not_connected")
		return
	}
	pod, err := client.CoreV1().Pods(namespace).Get(r.Context(), podName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		refuse(http.StatusNotFound, audit.Failed, "pod_not_found")
		return
	case err != nil:
		refuse(http.StatusBadGateway, audit.Failed, "unavailable")
		return
	}
	container := strings.TrimSpace(req.Container)
	if container == "" {
		container = defaultContainer(pod)
	}
	details["container"] = container
	cs := containerStatus(pod, container)
	if !hasContainer(pod, container) {
		refuse(http.StatusBadRequest, audit.Failed, "container_not_found")
		return
	}
	if cs == nil || cs.State.Running == nil {
		refuse(http.StatusBadRequest, audit.Failed, "not_ready")
		return
	}

	if !s.execSessions.acquire(claims.UserID) {
		details["max_sessions"] = maxExecSessionsPerUser
		refuse(http.StatusTooManyRequests, audit.RateLimited, "too_many_sessions")
		return
	}
	defer s.execSessions.release(claims.UserID)

	requestID := logging.RequestIDFrom(r.Context())
	rec := s.startExecRecording(r, claims.Username, namespace, podName, container, requestID, models.RecordingModeCommand)
	defer rec.Close()
	if rec == nil && claims.APIKey != nil {
		// Same rule as the shell: what a key runs is always recorded.
		refuse(http.StatusServiceUnavailable, audit.Failed, "recording_unavailable")
		return
	}
	// The recording reads like a terminal: the command line, then its output.
	rec.Write([]byte("$ " + quoteArgv(req.Command) + "\r\n"))
	tee := func(p []byte) { rec.Write(bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))) }
	stdout, stderr := &capped{tee: tee}, &capped{tee: tee}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()
	start := time.Now()
	MetricsExecIncr()
	err = streamPodCommand(ctx, kubeFor(r), namespace, podName, container, req.Command, stdout, stderr)
	out, outBytes, outCut := stdout.result()
	errOut, errBytes, errCut := stderr.result()
	resp := execCommandResponse{Stdout: out, Stderr: errOut, ExitCode: -1, Truncated: outCut || errCut,
		DurationMs: time.Since(start).Milliseconds()}
	var exitErr utilexec.ExitError
	var failed error
	switch {
	case err == nil:
		resp.ExitCode = 0
	case errors.As(err, &exitErr):
		resp.ExitCode = exitErr.ExitStatus()
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && r.Context().Err() == nil:
		// Cut at the time limit. Kubernetes doesn't kill a TTY-less exec'd process, so it may run on.
		resp.Truncated = true
	default:
		failed = err
	}
	if rec != nil {
		res := rec.Close()
		details["recording_id"] = res.SessionID
		d := audit.D{"pod": podName, "container": container, "size_bytes": res.SizeBytes, "duration_ms": res.Duration.Milliseconds()}
		if res.Truncated {
			d["truncate_reason"] = res.TruncateReason
		}
		s.recordRecordingCreateAudit(r, namespace, res.SessionID, audit.Success, "", d)
	}
	details["exit_code"] = resp.ExitCode
	details["bytes_out"] = outBytes + errBytes
	details["duration_ms"] = resp.DurationMs
	if failed != nil {
		// The error text comes from the API server / kubelet, not from the command line.
		s.recordExecAudit(r, namespace, podName, audit.Failed, "exec_failed", failDetails(failed, details))
		writeError(w, http.StatusBadGateway, "exec_failed")
		return
	}
	s.recordExecAudit(r, namespace, podName, audit.Success, "", details)
	writeJSON(w, http.StatusOK, resp)
}

func hasContainer(pod *corev1.Pod, name string) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// quoteArgv renders argv the way a shell user would type it, for the recording only.
func quoteArgv(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`;&|<>(){}*?!#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
