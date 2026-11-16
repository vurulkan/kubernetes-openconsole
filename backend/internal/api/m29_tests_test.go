package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"k8s-dashboard/backend/internal/kube"
)

const deployLogsPath = "/ws/namespaces/team-a/deployments/web/logs"

// webDeployment creates deployment web (app=web) with the given pods.
func (e *testEnv) webDeployment(phase corev1.PodPhase, pods map[string][]string) {
	e.t.Helper()
	ctx := context.Background()
	sel := map[string]string{"app": "web"}
	if _, err := e.client.AppsV1().Deployments("team-a").Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}},
	}, metav1.CreateOptions{}); err != nil {
		e.t.Fatal(err)
	}
	for name, containers := range pods {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a", Labels: sel}, Status: corev1.PodStatus{Phase: phase}}
		for _, c := range containers {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
		}
		if _, err := e.client.CoreV1().Pods("team-a").Create(ctx, p, metav1.CreateOptions{}); err != nil {
			e.t.Fatal(err)
		}
	}
}

// The deployment log socket follows every pod × container of the selector
// (not other pods), reports each stream on its own, ends with "interrupted"
// while a pod still runs, and is audited once with the pod count.
func TestDeploymentLogsWSFollowsEveryContainer(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	e.webDeployment(corev1.PodRunning, map[string][]string{"web-1": {"app", "sidecar"}, "web-2": {"app"}})
	_, _ = e.client.CoreV1().Pods("team-a").Create(context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "team-a"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "x"}}}},
		metav1.CreateOptions{})

	frames := dialLogs(t, e, root, deployLogsPath)
	if len(frames) != 4 {
		t.Fatalf("frames = %+v", frames)
	}
	// client-go's fake log body has no timestamps: each stream reports it as a note.
	var streams []string
	for _, f := range frames[:3] {
		if f.T != "error" || f.Reason != "unavailable" || f.Msg != "fake logs" {
			t.Fatalf("stream frame = %+v", f)
		}
		streams = append(streams, f.Pod+"/"+f.C)
	}
	sort.Strings(streams)
	if strings.Join(streams, " ") != "web-1/app web-1/sidecar web-2/app" {
		t.Fatalf("streams = %v", streams)
	}
	if end := frames[3]; end.T != "end" || end.Reason != "interrupted" || !end.Retry {
		t.Fatalf("end = %+v", end)
	}
	e.waitAudit("deployment.logs.success", `"pods":2`)
}

// When every pod has finished, the view ends for good; a resumed view (a
// reconnect) is not audited again.
func TestDeploymentLogsWSFinishedAndResume(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	e.webDeployment(corev1.PodSucceeded, map[string][]string{"web-1": {"app"}})
	frames := dialLogs(t, e, root, deployLogsPath+"?resume=true&sinceTime=2026-01-01T00:00:00Z&skip=2&tail=5")
	if len(frames) != 2 || frames[1].T != "end" || frames[1].Reason != "container_terminated" || frames[1].Retry {
		t.Fatalf("frames = %+v", frames)
	}
	e.noAudit("deployment.logs.success")
}

// Refusals: each says why in a frame (a browser can't read a failed
// upgrade's status) and plain HTTP gets the status code.
func TestDeploymentLogsWSRefusals(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	refused := func(token, path, reason string, status int) {
		t.Helper()
		frames := dialLogs(t, e, token, path)
		if len(frames) != 1 || frames[0].T != "error" || frames[0].Reason != reason {
			t.Fatalf("%s: frames = %+v, want %s", path, frames, reason)
		}
		e.expect("GET", path, token, nil, status)
	}
	// No such deployment: reported as unavailable, not 404.
	refused(root, "/ws/namespaces/team-a/deployments/nope/logs", "unavailable", http.StatusServiceUnavailable)
	// A deployment without pods.
	e.webDeployment(corev1.PodRunning, nil)
	refused(root, deployLogsPath, "no_pods", http.StatusNotFound)
	// The pod list fails.
	e.client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("etcd timeout")
	})
	refused(root, deployLogsPath, "unavailable", http.StatusServiceUnavailable)

	// RBAC: deployments:get AND pods:logs, each alone is not enough.
	logsOnlyID, logsOnly := e.user("logs-only", false)
	e.grant(logsOnlyID, [4]any{0, "team-a", "pods", "logs"})
	getOnlyID, getOnly := e.user("get-only", false)
	e.grant(getOnlyID, [4]any{0, "team-a", "deployments", "get"})
	refused(logsOnly, deployLogsPath, "forbidden", http.StatusForbidden)
	refused(getOnly, deployLogsPath, "forbidden", http.StatusForbidden)
	e.waitAudit("deployment.logs.denied", "web")
}

// logAPI is a Kubernetes API server with deployment team-a/web, its running
// pod web-1 and that pod's followed log: lines (−1 = until the request ends)
// of size bytes, one every `every`. ended is closed when a log request ends
// before its last line (the viewer's streams were cancelled).
func logAPI(t *testing.T, lines, size int, every time.Duration) (client kubernetes.Interface, ended chan struct{}) {
	t.Helper()
	ended = make(chan struct{})
	var once sync.Once
	sel := map[string]string{"app": "web"}
	deploy := appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}}}
	pods := corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "team-a", Labels: sel},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}}}
	pad := strings.Repeat("x", size)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/team-a/deployments/web":
			_ = json.NewEncoder(w).Encode(deploy)
		case "/api/v1/namespaces/team-a/pods":
			_ = json.NewEncoder(w).Encode(pods)
		case "/api/v1/namespaces/team-a/pods/web-1/log":
			w.Header().Set("Content-Type", "text/plain")
			for i := 0; lines < 0 || i < lines; i++ {
				if r.Context().Err() != nil {
					once.Do(func() { close(ended) })
					return
				}
				ts := time.Now().UTC().Format(time.RFC3339Nano)
				if _, err := fmt.Fprintf(w, "%s line-%d %s\n", ts, i, pad); err != nil {
					once.Do(func() { close(ended) })
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(every)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(hs.Close)
	c, err := kubernetes.NewForConfig(&rest.Config{Host: hs.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c, ended
}

// realServer serves the router the way cmd/server/main.go does: an
// http.Server with ReadTimeout = WriteTimeout (60 s there, no IdleTimeout),
// scaled down to timeout.
func realServer(t *testing.T, e *testEnv, timeout time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: e.server.Router(), ReadTimeout: timeout, WriteTimeout: timeout}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return "ws://" + ln.Addr().String()
}

const serverTimeout = 300 * time.Millisecond

// A followed log outlives the server's ReadTimeout and WriteTimeout: those
// deadlines bound reading the request and writing a plain response, and the
// WebSocket upgrade clears them; the socket then has only its per-frame
// write deadline (logWriteTimeout).
func TestFollowedLogOutlivesServerTimeouts(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	client, _ := logAPI(t, 12, 10, 100*time.Millisecond) // 1.2 s of log = 4 × the server timeouts
	e.server.clusters.Put(e.alphaID, kube.NewManagerWithClient(client))
	base := realServer(t, e, serverTimeout)

	start := time.Now()
	conn, _, err := websocket.DefaultDialer.Dial(base+deployLogsPath, http.Header{"Authorization": {"Bearer " + root}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	lines := 0
	var last logFrame
	for {
		var f logFrame
		if err := conn.ReadJSON(&f); err != nil {
			t.Fatalf("socket ended after %d lines, %s: %v", lines, time.Since(start).Round(time.Millisecond), err)
		}
		if f.T == "line" {
			if want := fmt.Sprintf("line-%d", lines); !strings.HasPrefix(f.Text, want) || f.Pod != "web-1" {
				t.Fatalf("line %d = %+v", lines, f)
			}
			lines++
			continue
		}
		last = f
		break
	}
	if lines != 12 || last.T != "end" || last.Reason != "interrupted" || !last.Retry {
		t.Fatalf("%d lines, then %+v", lines, last)
	}
	if took := time.Since(start); took < 3*serverTimeout {
		t.Fatalf("socket lived %s, not longer than the server timeouts", took)
	}
}

// A quiet Live Events socket outlives the server timeouts too, and still
// delivers the next event.
func TestQuietEventsSocketOutlivesServerTimeouts(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	base := realServer(t, e, serverTimeout)
	conn, _, err := websocket.DefaultDialer.Dial(base+"/ws/events", http.Header{"Authorization": {"Bearer " + root}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(3 * serverTimeout)
	e.alpha.EventBus().Publish(kube.ResourceEvent{Verb: "added", Kind: "Pod", Namespace: "team-a", Name: "late"})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ev kube.ResourceEvent
	if err := conn.ReadJSON(&ev); err != nil || ev.Name != "late" {
		t.Fatalf("event after a quiet %s = %+v, %v", 3*serverTimeout, ev, err)
	}
}

// A viewer that stops reading is cut by logWriteTimeout (not by the server
// timeouts), and the Kubernetes log stream behind it ends.
func TestSlowLogViewerIsCut(t *testing.T) {
	old := logWriteTimeout
	logWriteTimeout = 200 * time.Millisecond
	defer func() { logWriteTimeout = old }()
	e := newTestEnv(t)
	_, root := e.user("root", true)
	client, ended := logAPI(t, -1, 64<<10, 0) // endless 64 KB lines
	e.server.clusters.Put(e.alphaID, kube.NewManagerWithClient(client))
	base := realServer(t, e, time.Minute) // the server timeouts play no part

	conn, _, err := websocket.DefaultDialer.Dial(base+deployLogsPath, http.Header{"Authorization": {"Bearer " + root}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() // never read
	select {
	case <-ended:
	case <-time.After(5 * time.Second): // logWriteTimeout is 200 ms; the default 10 s would fail here
		t.Fatal("the log stream of a viewer that reads nothing is still open")
	}
	// The handler ends too (before logWriteTimeout is restored: it reads it).
	drained, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.server.Drain(drained)
	if drained.Err() != nil {
		t.Fatal("the log handler of a cut viewer is still running")
	}
}
