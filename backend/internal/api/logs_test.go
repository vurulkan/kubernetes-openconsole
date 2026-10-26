package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// A resumed stream restarts at the second of the last line seen; nothing is lost or repeated.
func TestResumeFilter(t *testing.T) {
	at := func(ns int) time.Time { return time.Date(2026, 1, 1, 0, 0, 5, ns, time.UTC) }
	// The viewer saw lines up to .300, two of them at exactly .300.
	f := resumeFilter{since: at(300), skip: 2}
	var kept []int
	for _, ns := range []int{0, 100, 300, 300, 300, 301, 999} {
		if f.keep(at(ns)) {
			kept = append(kept, ns)
		}
	}
	if got := fmt.Sprint(kept); got != "[300 301 999]" {
		t.Fatalf("kept %s, want [300 301 999]", got)
	}
	if !(&resumeFilter{}).keep(at(0)) {
		t.Fatal("a fresh stream drops lines")
	}
}

func TestLogErrorReason(t *testing.T) {
	gr := schema.GroupResource{Resource: "pods"}
	for _, tc := range []struct {
		err      error
		previous bool
		want     string
	}{
		{apierrors.NewForbidden(gr, "p", errors.New("no")), false, "forbidden"},
		{apierrors.NewBadRequest(`container x is not valid for pod p`), false, "container_not_found"},
		{apierrors.NewBadRequest(`previous terminated container "app" in pod "p" not found`), true, "previous_unavailable"},
		{apierrors.NewBadRequest(`container "app" in pod "p" is waiting to start: ContainerCreating`), false, "not_ready"},
		{apierrors.NewNotFound(gr, "p"), false, "pod_deleted"},
		{errors.New("dial tcp: refused"), false, "unavailable"},
	} {
		if got := logErrorReason(tc.err, tc.previous); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

func TestWillRestart(t *testing.T) {
	exited := func(code int32) *corev1.ContainerStatus {
		return &corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}}}
	}
	pod := func(policy corev1.RestartPolicy, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{RestartPolicy: policy, InitContainers: []corev1.Container{{Name: "init"}}}, Status: corev1.PodStatus{Phase: phase}}
	}
	if !willRestart(pod(corev1.RestartPolicyAlways, corev1.PodRunning), exited(0)) {
		t.Error("Always + exit 0 restarts")
	}
	if !willRestart(pod(corev1.RestartPolicyOnFailure, corev1.PodRunning), exited(137)) {
		t.Error("OnFailure + exit 137 restarts")
	}
	if willRestart(pod(corev1.RestartPolicyOnFailure, corev1.PodRunning), exited(0)) {
		t.Error("OnFailure + exit 0 is done")
	}
	if willRestart(pod(corev1.RestartPolicyAlways, corev1.PodSucceeded), exited(1)) {
		t.Error("a finished pod does not restart")
	}
	init := exited(0)
	init.Name = "init"
	if willRestart(pod(corev1.RestartPolicyAlways, corev1.PodRunning), init) {
		t.Error("a completed init container does not restart")
	}
}

func TestPumpSplitsLinesFromKubeletNotes(t *testing.T) {
	in := "2026-01-01T00:00:01.5Z hello world\nunable to retrieve container logs for containerd://x\n2026-01-01T00:00:02Z bye\n"
	var got []logFrame
	note := pump(context.Background(), strings.NewReader(in), "p", "c", resumeFilter{}, func(f logFrame) { got = append(got, f) })
	if note != "unable to retrieve container logs for containerd://x" {
		t.Fatalf("note = %q", note)
	}
	if len(got) != 2 || got[0].Text != "hello world" || got[0].TS != "2026-01-01T00:00:01.500000000Z" || got[1].Text != "bye" {
		t.Fatalf("lines = %+v", got)
	}
}

func dialLogs(t *testing.T, e *testEnv, token, path string) []logFrame {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(e.http.URL, "http") + path
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var frames []logFrame
	for {
		var f logFrame
		if err := conn.ReadJSON(&f); err != nil {
			return frames
		}
		frames = append(frames, f)
	}
}

func TestPodLogFrames(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)

	// client-go's fake returns "fake logs": no timestamp, so not a container line but a note.
	frames := dialLogs(t, e, admin, "/ws/namespaces/team-a/pods/api-1/logs?container=app")
	if len(frames) != 1 || frames[0].T != "end" || frames[0].Reason != "container_terminated" || !frames[0].Retry || frames[0].Msg != "fake logs" {
		t.Fatalf("live frames = %+v", frames)
	}

	frames = dialLogs(t, e, admin, "/ws/namespaces/team-a/pods/api-1/logs?container=app&previous=true")
	if len(frames) != 1 || frames[0].T != "error" || frames[0].Reason != "previous_unavailable" || frames[0].Retry {
		t.Fatalf("previous frames = %+v", frames)
	}

	job := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "batch-x", Namespace: "team-a", Labels: map[string]string{"job-name": "batch"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "work"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	if _, err := e.client.CoreV1().Pods("team-a").Create(context.Background(), job, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	frames = dialLogs(t, e, admin, "/ws/namespaces/team-a/jobs/batch/logs")
	if len(frames) != 2 || frames[0].T != "error" || frames[0].Pod != "batch-x" || frames[0].C != "work" {
		t.Fatalf("job frames = %+v", frames)
	}
	if end := frames[1]; end.Reason != "container_terminated" || end.Retry {
		t.Fatalf("finished job end = %+v", end)
	}
}

// A reconnect after a drop is not a new audit event; a refused socket says why in a frame.
func TestPodLogsResumeAndRefusal(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "logs"})

	dialLogs(t, e, bob, "/ws/namespaces/team-a/pods/api-1/logs?container=app&resume=true&sinceTime=2026-01-01T00:00:00.000000000Z&skip=1")
	time.Sleep(100 * time.Millisecond)
	e.noAudit("pod.logs.success")

	frames := dialLogs(t, e, bob, "/ws/namespaces/team-b/pods/api-1/logs")
	if len(frames) != 1 || frames[0].T != "error" || frames[0].Reason != "forbidden" {
		t.Fatalf("refused frames = %+v", frames)
	}
	e.waitAudit("pod.logs.denied", "api-1")
	// Plain HTTP (no upgrade) still gets the status code.
	e.expect("GET", "/ws/namespaces/team-b/pods/api-1/logs", bob, nil, http.StatusForbidden)
}
