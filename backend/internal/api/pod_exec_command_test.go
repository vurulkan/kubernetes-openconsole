package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilexec "k8s.io/client-go/util/exec"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// fakeCommands stands in for the API server's exec: what each program prints and returns.
func fakeCommands(t *testing.T) {
	t.Helper()
	prev := streamPodCommand
	t.Cleanup(func() { streamPodCommand = prev })
	streamPodCommand = func(ctx context.Context, _ *kube.Manager, _, _, _ string, argv []string, stdout, stderr io.Writer) error {
		switch argv[0] {
		case "cat":
			_, _ = io.WriteString(stdout, "NAME=Alpine\nID=alpine\n")
			return nil
		case "sh": // sh -c '<secret>'
			_, _ = io.WriteString(stderr, "no such file\n")
			return utilexec.CodeExitError{Err: errors.New("command terminated with exit code 2"), Code: 2}
		case "sleep":
			_, _ = io.WriteString(stdout, "started\n")
			<-ctx.Done()
			return ctx.Err()
		case "yes":
			chunk := []byte(strings.Repeat("y\n", 32<<10))
			for i := 0; i < 24; i++ { // 1.5 MiB
				_, _ = stdout.Write(chunk)
			}
			return nil
		}
		return errors.New("error dialing backend")
	}
}

// runningPod adds team-a/app-1 with a running container "app".
func (e *testEnv) runningPod() {
	e.t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: "sidecar", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}},
		}},
	}
	if _, err := e.client.CoreV1().Pods("team-a").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		e.t.Fatal(err)
	}
}

func execResult(t *testing.T, body string) execCommandResponse {
	t.Helper()
	var out execCommandResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return out
}

const execPath = "/api/namespaces/team-a/pods/app-1/exec"

func TestPodExecCommand(t *testing.T) {
	e := newTestEnv(t)
	fakeCommands(t)
	e.runningPod()
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "exec"})

	out := execResult(t, e.expect("POST", execPath, bob, map[string]any{"command": []string{"cat", "/etc/os-release"}}, http.StatusOK))
	if out.Stdout != "NAME=Alpine\nID=alpine\n" || out.ExitCode != 0 || out.Truncated {
		t.Fatalf("cat = %+v", out)
	}
	ok := e.waitAudit("pod.exec.success", `"program":"cat"`)
	if ok.Details["mode"] != "command" || ok.Details["container"] != "app" || ok.Details["recording_id"] == "" || strings.Contains(auditText(ok), "os-release") {
		t.Fatalf("audit = %+v", ok.Details)
	}

	// A non-zero exit is an answer, not an error; the full command stays out of the audit log.
	out = execResult(t, e.expect("POST", execPath, bob, map[string]any{"command": []string{"sh", "-c", "cat /run/hunter2"}}, http.StatusOK))
	if out.ExitCode != 2 || out.Stderr != "no such file\n" {
		t.Fatalf("sh = %+v", out)
	}
	if l := e.waitAudit("pod.exec.success", `"program":"sh"`); strings.Contains(auditText(l), "hunter2") {
		t.Fatalf("command text in audit: %s", auditText(l))
	}
	// …and is in the recording, as a command line.
	recs, _, _ := e.server.recorder.List(context.Background(), models.RecordingFilter{})
	var cast []byte
	for _, r := range recs {
		if r.Mode != models.RecordingModeCommand {
			t.Fatalf("recording mode = %q", r.Mode)
		}
		full, _ := e.store.GetRecording(context.Background(), r.ID)
		if b, _ := os.ReadFile(full.Path); strings.Contains(string(b), "hunter2") {
			cast = b
		}
	}
	if !strings.Contains(string(cast), `$ sh -c 'cat /run/hunter2'`) {
		t.Fatalf("no recording of the sh command:\n%s", cast)
	}

	out = execResult(t, e.expect("POST", execPath, bob, map[string]any{"command": []string{"sleep", "60"}, "timeoutSeconds": 1}, http.StatusOK))
	if out.ExitCode != -1 || !out.Truncated || out.Stdout != "started\n" {
		t.Fatalf("timeout = %+v", out)
	}
	out = execResult(t, e.expect("POST", execPath, bob, map[string]any{"command": []string{"yes"}}, http.StatusOK))
	if len(out.Stdout) != execCommandMaxOutput || !out.Truncated || out.ExitCode != 0 {
		t.Fatalf("big output: %d bytes, %+v", len(out.Stdout), out.Truncated)
	}
	e.waitAudit("pod.exec.success", `"bytes_out":1572864`)

	e.expect("POST", execPath, bob, map[string]any{"command": []string{"boom"}}, http.StatusBadGateway)
	e.waitAudit("pod.exec.failed", "exec_failed")

	for _, c := range []struct {
		body any
		want int
		why  string
	}{
		{map[string]any{"command": []string{}}, 400, ""},
		{map[string]any{"command": "cat /etc/os-release"}, 400, ""},
		{map[string]any{"command": []string{"cat"}, "timeoutSeconds": 121}, 400, ""},
		{map[string]any{"command": []string{"cat"}, "timeoutSeconds": 0}, 400, ""},
		{map[string]any{"command": []string{"cat"}, "container": "nope"}, 400, "container_not_found"},
		{map[string]any{"command": []string{"cat"}, "container": "sidecar"}, 400, "not_ready"},
	} {
		if body := e.expect("POST", execPath, bob, c.body, c.want); !strings.Contains(body, c.why) {
			t.Errorf("%v: %s", c.body, body)
		}
	}
	e.expect("POST", "/api/namespaces/team-a/pods/gone/exec", bob, map[string]any{"command": []string{"cat"}}, http.StatusNotFound)

	// No permission, then the feature switched off: refused before anything runs.
	if body := e.expect("POST", "/api/namespaces/team-b/pods/api-1/exec", bob, map[string]any{"command": []string{"cat"}}, http.StatusForbidden); !strings.Contains(body, reasonForbidden) {
		t.Fatal(body)
	}
	e.waitAudit("pod.exec.denied", `"mode":"command"`)
	SetDisabledFeatures([]string{FeaturePodExec})
	t.Cleanup(func() { SetDisabledFeatures(nil) })
	if body := e.expect("POST", execPath, bob, map[string]any{"command": []string{"cat"}}, http.StatusForbidden); !strings.Contains(body, reasonFeatureDisabled) {
		t.Fatal(body)
	}
}

// One command counts as an open shell: at the limit, 429.
func TestPodExecCommandSessionLimit(t *testing.T) {
	e := newTestEnv(t)
	fakeCommands(t)
	e.runningPod()
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "exec"})
	for i := 0; i < maxExecSessionsPerUser; i++ {
		e.server.execSessions.acquire(bobID)
	}
	e.expect("POST", execPath, bob, map[string]any{"command": []string{"cat"}}, http.StatusTooManyRequests)
	e.waitAudit("pod.exec.rate_limited", "too_many_sessions")
}
