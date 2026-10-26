package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/store"
)

// A list is one event with its own fields: action, verb, outcome, the
// request's cluster and who / from where.
func TestReadAuditFields(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "deployments", "list"})

	e.expect("GET", "/api/namespaces/team-a/deployments", bob, nil, http.StatusOK)
	got := e.waitAudit("deployment.list.success", "*")
	if got.Verb != "list" || got.ResourceType != "deployment" || got.Namespace != "team-a" ||
		got.Cluster != "alpha" || got.ClusterID != 1 || got.User != "bob" || got.AuthSource != "local" ||
		got.SourceIP != "127.0.0.1" || got.UserAgent == "" || got.RequestID == "" {
		t.Fatalf("list event = %+v", got)
	}

	// A read without the grant is audited as denied.
	e.expect("GET", "/api/namespaces/team-b/deployments", bob, nil, http.StatusForbidden)
	if d := e.waitAudit("deployment.list.denied", "*"); d.Reason != "forbidden" || d.Namespace != "team-b" {
		t.Fatalf("denied = %+v", d)
	}
	e.expect("GET", "/api/namespaces/team-a/pods/api-1", bob, nil, http.StatusForbidden)
	e.waitAudit("pod.get.denied", "api-1")
}

// The UI's own refreshes are not audited; the list the user opened is.
func TestAutoRefreshNotAudited(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	req, _ := http.NewRequest("GET", e.http.URL+"/api/namespaces/team-a/pods", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set(refreshHeader, "auto")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	e.noAudit("pod.list")
	e.expect("GET", "/api/namespaces/team-a/pods", admin, nil, http.StatusOK)
	e.waitAudit("pod.list.success", "*")
}

// Details are fields, not a "(k=v)" suffix on the resource name.
func TestWriteAuditDetails(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/namespaces/team-a/deployments/api/restart", admin, nil, http.StatusOK)
	got := e.waitAudit("deployment.restart.success", "restarted_at")
	if got.ResourceName != "api" || got.Details["restarted_at"] == "" || got.Cluster != "alpha" {
		t.Fatalf("restart = %+v", got)
	}
	// A failure carries a reason and the error message as fields.
	e.do("POST", "/api/namespaces/team-a/deployments/missing/restart", admin, nil)
	got = e.waitAudit("deployment.restart.failed", "missing")
	if got.Reason != "not_found" || got.Details["error"] == nil {
		t.Fatalf("failed restart = %+v", got)
	}
}

// Cluster-independent actions carry no cluster, even when the admin has one
// selected; a grant carries its own cluster, not the admin's.
func TestAuditClusterIsTheTarget(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	e.expect("POST", "/api/cluster/select", admin, map[string]int{"clusterId": 1}, http.StatusOK) // alpha

	e.expect("POST", "/api/admin/users", admin, map[string]any{"username": "ali", "password": "Passw0rd!long", "source": "local"}, http.StatusCreated)
	if got := e.waitAudit("user.create.success", "ali"); got.Cluster != "" || got.ClusterID != 0 {
		t.Fatalf("user.create cluster = %q", got.Cluster)
	}
	roleID, _ := e.store.CreateRole(context.Background(), "ops", "")
	e.expect("POST", "/api/admin/roles/"+itoa(int64(roleID))+"/permissions", admin,
		map[string]any{"clusterId": 2, "namespace": "team-a", "resource": "deployments", "action": "restart"}, http.StatusCreated)
	got := e.waitAudit("permission.create.success", "ops")
	if got.Cluster != "beta" || got.ClusterID != 2 || got.Namespace != "team-a" || got.Details["grant"] != "deployments:restart" {
		t.Fatalf("permission.create = %+v", got)
	}
	e.expect("POST", "/api/admin/roles/"+itoa(int64(roleID))+"/permissions", admin,
		map[string]any{"namespace": "*", "resource": "pods", "action": "list"}, http.StatusCreated)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := e.store.ListAuditLogsFiltered(context.Background(), 10, 0,
			store.AuditFilter{Action: "permission.create", ActionExact: true})
		if len(logs) == 2 {
			if logs[0].Cluster != "" { // all clusters
				t.Fatalf("all-cluster grant = %+v", logs[0])
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("second grant not audited")
}

// "Previous logs" reads the crashed container instance once, without
// following, and the audit record says so.
func TestPreviousPodLogs(t *testing.T) {
	if o := (models.PodLogOptions{Previous: true}).ToKube(); !o.Previous || o.Follow {
		t.Fatalf("previous log options = %+v, want previous without follow", o)
	}
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	wsURL := "ws" + strings.TrimPrefix(e.http.URL, "http") + "/ws/namespaces/team-a/pods/api-1/logs?container=app&previous=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": {"Bearer " + admin}})
	if err != nil {
		t.Fatalf("dial logs: %v", err)
	}
	conn.Close()
	if got := e.waitAudit("pod.logs", `"previous":true`); got.Details["container"] != "app" {
		t.Fatalf("previous logs audit = %+v", got)
	}
}

// Without ?container= a multi-container pod's log opens on the container
// kubectl would pick (annotation, else the first), instead of failing.
func TestPodLogsDefaultContainer(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	two := []corev1.Container{{Name: "app"}, {Name: "sidecar"}}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "team-a"}, Spec: corev1.PodSpec{Containers: two}},
		{ObjectMeta: metav1.ObjectMeta{Name: "annotated", Namespace: "team-a",
			Annotations: map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"}}, Spec: corev1.PodSpec{Containers: two}},
	} {
		if _, err := e.client.CoreV1().Pods("team-a").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for pod, want := range map[string]string{"plain": "app", "annotated": "sidecar"} {
		wsURL := "ws" + strings.TrimPrefix(e.http.URL, "http") + "/ws/namespaces/team-a/pods/" + pod + "/logs"
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": {"Bearer " + admin}})
		if err != nil {
			t.Fatalf("dial %s: %v", pod, err)
		}
		conn.Close()
		if got := e.waitAudit("pod.logs", pod); got.Details["container"] != want {
			t.Fatalf("%s: container = %v, want %s", pod, got.Details["container"], want)
		}
	}
}
