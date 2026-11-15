package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
)

// Clusters in newTestEnv: 1 = alpha (default), 2 = beta.

func patchedDeployments(c *fake.Clientset) int {
	n := 0
	for _, a := range c.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "deployments" {
			n++
		}
	}
	return n
}

// A tab sends the cluster it shows: another tab switching the user's cluster
// (users.active_cluster_id) doesn't move this tab's actions. Without the
// header the stored pick still applies (old clients, curl with a session).
func TestTabClusterHeaderWinsOverStoredPick(t *testing.T) {
	e := newTestEnv(t)
	rootID, root := e.user("root", true)
	if err := e.store.SetUserActiveCluster(context.Background(), rootID, 2); err != nil { // "the other tab" picked beta
		t.Fatal(err)
	}
	alpha := strconv.Itoa(e.alphaID)

	code, _ := e.doHeader("POST", "/api/namespaces/team-a/deployments/api/restart", root, map[string]string{clusterHeader: alpha})
	if code != http.StatusOK {
		t.Fatalf("restart = %d", code)
	}
	if patchedDeployments(e.client) != 1 {
		t.Fatal("the restart did not reach the tab's cluster (alpha)")
	}
	if l := e.waitAudit("deployment.restart.success", "api"); l.Cluster != "alpha" {
		t.Fatalf("audit cluster = %q, want alpha", l.Cluster)
	}

	// No header: the stored pick (beta), and the response names it for the tab to keep.
	req, _ := http.NewRequest("GET", e.http.URL+"/api/namespaces/team-a/pods", nil)
	req.Header.Set("Authorization", "Bearer "+root)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get(clusterHeader); got != "2" {
		t.Fatalf("response %s = %q, want 2", clusterHeader, got)
	}
}

// A WebSocket can't carry headers: the ticket takes the tab's cluster along.
func TestWSTicketCarriesTabCluster(t *testing.T) {
	e := newTestEnv(t)
	rootID, root := e.user("root", true)
	_ = e.store.SetUserActiveCluster(context.Background(), rootID, 2)
	path := "/ws/namespaces/team-a/pods/api-1/logs"
	req, _ := http.NewRequest("POST", e.http.URL+"/api/ws-ticket", strings.NewReader(`{"path":"`+path+`"}`))
	req.Header.Set("Authorization", "Bearer "+root)
	req.Header.Set(clusterHeader, strconv.Itoa(e.alphaID))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Ticket string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+path+"?container=app&ticket="+out.Ticket, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if l := e.waitAudit("pod.logs.success", "api-1"); l.Cluster != "alpha" {
		t.Fatalf("log socket ran on %q, want alpha", l.Cluster)
	}
}

// A session naming a cluster its grants don't cover is refused and audited.
func TestTabClusterHeaderFollowsGrants(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{2, "team-a", "pods", "list"}) // beta only
	if code, _ := e.doHeader("GET", "/api/namespaces/team-a/pods", bob, map[string]string{clusterHeader: strconv.Itoa(e.alphaID)}); code != http.StatusForbidden {
		t.Fatalf("pods on alpha = %d, want 403", code)
	}
	e.waitAudit("cluster.use.denied", "alpha")
	if code, _ := e.doHeader("GET", "/api/namespaces/team-a/pods", bob, map[string]string{clusterHeader: "2"}); code != http.StatusOK {
		t.Fatalf("pods on beta = %d", code)
	}
}

// Kubernetes errors on reads keep their meaning instead of a bare 404 / 503.
func TestReadErrorsKeepTheirMeaning(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	forbid := func(verb, resource string) {
		e.client.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("no rule"))
		})
	}
	forbid("list", "ingresses")
	forbid("get", "pods")
	e.client.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewTimeoutError("slow", 1)
	})
	if out := e.expect("GET", "/api/namespaces/team-a/ingresses", root, nil, http.StatusForbidden); !strings.Contains(out, reasonClusterForbidden) {
		t.Fatalf("ingresses body = %s", out)
	}
	e.expect("GET", "/api/namespaces/team-a/pods/api-1", root, nil, http.StatusForbidden)
	e.expect("GET", "/api/namespaces/team-a/services", root, nil, http.StatusGatewayTimeout)
	e.expect("GET", "/api/namespaces/team-a/deployments/missing", root, nil, http.StatusNotFound)
}

// Picking a cluster asks it once: a refused token fails the pick (it used to say ok).
func TestClusterSelectChecksTheCluster(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	broken := fake.NewSimpleClientset()
	broken.PrependReactor("list", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewUnauthorized("token revoked")
	})
	e.server.clusters.Put(2, kube.NewManagerWithClient(broken))
	e.expect("POST", "/api/cluster/select", root, map[string]int{"clusterId": 2}, http.StatusBadGateway)
	e.waitAudit("cluster.select.failed", "unreachable")
}

// Editing a cluster's credentials ends the Live Events sockets on it, so the
// panel reconnects instead of staying open with nothing arriving.
func TestClusterEditEndsLiveEvents(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+"/ws/events",
		http.Header{"Authorization": {"Bearer " + root}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(50 * time.Millisecond) // subscribed
	e.server.clusters.Invalidate(e.alphaID)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	var ne interface{ Timeout() bool }
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("socket still open after the cluster was reconnected: %v", err)
	}
}

// A workload log view follows at most maxLogPods pods (ready ones first) and says so.
func TestWorkloadLogsFollowAtMostMaxPods(t *testing.T) {
	e := newTestEnv(t)
	_, root := e.user("root", true)
	ctx := context.Background()
	sel := map[string]string{"app": "big"}
	_, _ = e.client.AppsV1().Deployments("team-a").Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "team-a"},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}},
	}, metav1.CreateOptions{})
	for i := 0; i < maxLogPods+5; i++ {
		_, _ = e.client.CoreV1().Pods("team-a").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("big-%02d", i), Namespace: "team-a", Labels: sel},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		}, metav1.CreateOptions{})
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+"/ws/namespaces/team-a/deployments/big/logs",
		http.Header{"Authorization": {"Bearer " + root}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var first logFrame
	if err := conn.ReadJSON(&first); err != nil {
		t.Fatal(err)
	}
	if first.T != "note" || first.Reason != "pods_limited" || first.Shown != maxLogPods || first.Total != maxLogPods+5 {
		t.Fatalf("first frame = %+v", first)
	}
	streams := map[string]bool{}
	for {
		var f logFrame
		if err := conn.ReadJSON(&f); err != nil || f.T == "end" {
			break
		}
		if f.Pod != "" {
			streams[f.Pod] = true
		}
	}
	if len(streams) != maxLogPods {
		t.Fatalf("followed %d pods, want %d", len(streams), maxLogPods)
	}
}

func TestFollowedPodsReadyFirst(t *testing.T) {
	var pods []corev1.Pod
	for i := 0; i < maxLogPods+3; i++ {
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p-%02d", i)}}
		if i == maxLogPods+2 {
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		pods = append(pods, p)
	}
	got := followedPods(pods)
	if len(got) != maxLogPods || got[0].Name != fmt.Sprintf("p-%02d", maxLogPods+2) || got[1].Name != "p-00" {
		t.Fatalf("followed %d, first %s, second %s", len(got), got[0].Name, got[1].Name)
	}
}

// wsPair is a server-side socket and the client dialled to it.
func wsPair(t *testing.T) (server, client *websocket.Conn) {
	t.Helper()
	ch := make(chan *websocket.Conn, 1)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- c
	}))
	t.Cleanup(hs.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(hs.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server = <-ch
	t.Cleanup(func() { server.Close() })
	return server, client
}

// A viewer that stops reading (a frozen tab) ends its log view: the write
// times out and cancels the streams instead of blocking every pump forever.
func TestLogSocketGivesUpOnAStuckViewer(t *testing.T) {
	old := logWriteTimeout
	logWriteTimeout = 200 * time.Millisecond
	defer func() { logWriteTimeout = old }()
	server, _ := wsPair(t) // the client never reads
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := newLogSocket(server, cancel)
	go func() {
		line := logFrame{T: "line", Text: strings.Repeat("x", 64<<10)}
		for ctx.Err() == nil {
			sock.send(line)
		}
	}()
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the view is still blocked on a viewer that reads nothing")
	}
}

// Server sockets ping so a proxy's idle timeout doesn't cut a quiet shell or log.
func TestKeepAlivePings(t *testing.T) {
	server, client := wsPair(t)
	var pings atomic.Int32
	client.SetPingHandler(func(string) error { pings.Add(1); return nil })
	go func() {
		for {
			if _, _, err := client.ReadMessage(); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go keepAliveEvery(ctx, server, cancel, 20*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if pings.Load() < 3 {
		t.Fatalf("%d pings in 200 ms", pings.Load())
	}
}

// The session ends after the inactivity timeout, not a fixed time after
// sign-in: activity moves the deadline, a screen's automatic refresh doesn't.
func TestSessionInactivityTimeout(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("Passw0rd-123")
	id, _ := e.store.CreateUser(ctx, "dora", hash)
	_ = e.store.SetUserActiveCluster(ctx, id, 0)
	out := e.expect("POST", "/api/auth/login", "", map[string]string{"username": "dora", "password": "Passw0rd-123"}, http.StatusOK)
	var login struct{ Token string }
	_ = json.Unmarshal([]byte(out), &login)
	claims, err := auth.ParseToken(e.store.SigningKey(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Idle != 3600 {
		t.Fatalf("idle claim = %d, want 3600 (the 60-minute default)", claims.Idle)
	}
	if left := time.Until(claims.ExpiresAt.Time); left < 11*time.Hour {
		t.Fatalf("token lasts %s, want the 12 h absolute limit", left)
	}
	sessionExpiry := func() time.Time {
		rows, _ := e.store.ListSessions(ctx, id, false)
		return rows[0].ExpiresAt
	}
	// Pretend the session is 50 minutes old with 10 minutes left.
	if _, err := e.db.Conn.ExecContext(ctx, `UPDATE session_tokens SET expires_at = ? WHERE jti = ?`, time.Now().UTC().Add(10*time.Minute), claims.ID); err != nil {
		t.Fatal(err)
	}
	before := sessionExpiry()
	e.doHeader("GET", "/api/auth/me", login.Token, map[string]string{refreshHeader: "auto"})
	// A socket reconnecting on its own: an auto ticket request, then the connect.
	req, _ := http.NewRequest("POST", e.http.URL+"/api/ws-ticket", strings.NewReader(`{"path":"/ws/events"}`))
	req.Header.Set("Authorization", "Bearer "+login.Token)
	req.Header.Set(refreshHeader, "auto")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tk struct{ Ticket string }
	_ = json.NewDecoder(resp.Body).Decode(&tk)
	resp.Body.Close()
	if conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.http.URL, "http")+"/ws/events?ticket="+tk.Ticket, nil); err == nil {
		conn.Close()
	} else {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if !sessionExpiry().Equal(before) {
		t.Fatal("an automatic refresh or a socket reconnect extended the session")
	}
	e.expect("GET", "/api/auth/me", login.Token, nil, http.StatusOK)
	deadline := time.Now().Add(2 * time.Second)
	for time.Until(sessionExpiry()) < 55*time.Minute {
		if time.Now().After(deadline) {
			t.Fatalf("activity did not move the deadline: %s left", time.Until(sessionExpiry()))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Timed out: refused, and later activity doesn't bring it back.
	_, _ = e.db.Conn.ExecContext(ctx, `UPDATE session_tokens SET expires_at = ? WHERE jti = ?`, time.Now().UTC().Add(-time.Second), claims.ID)
	e.expect("GET", "/api/auth/me", login.Token, nil, http.StatusUnauthorized)
}
