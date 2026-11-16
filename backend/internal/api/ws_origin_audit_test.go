package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// With WS_ORIGIN_CHECK=enforce a socket from another site is refused, and nothing
// says it opened: no pod.logs success (it was audited before the upgrade up to
// 2.23.1) and no empty shell recording (one was started before the upgrade).
func TestRefusedOriginLeavesNoTrace(t *testing.T) {
	if err := SetOrigins("", "enforce"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetOrigins("", "") })
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	wsURL := "ws" + strings.TrimPrefix(e.http.URL, "http")
	evil := http.Header{"Authorization": {"Bearer " + admin}, "Origin": {"https://evil.example"}}

	_, resp, err := websocket.DefaultDialer.Dial(wsURL+"/ws/namespaces/team-a/pods/api-1/logs?container=app", evil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site log socket: err=%v resp=%v", err, resp)
	}
	e.noAudit("pod.logs.success")
	dialLogs(t, e, admin, "/ws/namespaces/team-a/pods/api-1/logs?container=app") // same site (no Origin): audited
	e.waitAudit("pod.logs.success", "api-1")

	// The shell: a real (unreachable) REST config gets the handler to the recording step.
	m := kube.NewManager()
	if err := m.ApplyCredentials(models.KubeCredentials{Method: "token", Server: "https://127.0.0.1:1", Token: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	e.server.clusters.Put(e.alphaID, m)
	_, resp, err = websocket.DefaultDialer.Dial(wsURL+"/ws/namespaces/team-a/pods/api-1/exec?container=app", evil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site shell: err=%v resp=%v", err, resp)
	}
	e.waitAudit("pod.exec.denied", "origin_not_allowed")
	recs, _, _ := e.server.recorder.List(context.Background(), models.RecordingFilter{})
	if len(recs) != 0 {
		t.Fatalf("refused shell left %d recording(s)", len(recs))
	}
}
