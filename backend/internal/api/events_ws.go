package api

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/rbac"
)

// handleEventsWS streams informer-driven ResourceEvents to the browser. The
// optional ?namespace=<ns> query param filters by namespace; cluster-scoped
// events (Namespace add/delete, cluster-level K8s Events) pass through for admins.
// Everyone else sees only what they may list (eventVisible).
//
// Protocol: server pushes JSON-encoded kube.ResourceEvent frames; the client
// may send pings but does not need to send anything. The server pings every
// 25s to keep intermediaries from reaping idle sockets.
func (s *Server) handleEventsWS(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var engine *rbac.Engine
	if !user.IsAdmin {
		// shortcut: grants are read when the socket opens; a revoked one applies on reconnect.
		if engine, ok = s.engineForRequest(r); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	clusterID := clusterIDFrom(r.Context())

	bus := kubeFor(r).EventBus()
	if bus == nil {
		writeError(w, http.StatusServiceUnavailable, "event bus unavailable")
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sub := bus.Subscribe(ns)
	defer bus.Unsubscribe(sub)

	// Reader goroutine — surfaces client disconnects as context cancellation.
	// Also drains any pings/messages the client sends so WriteControl can see
	// pong replies.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.SetReadLimit(1024)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	pinger := time.NewTicker(25 * time.Second)
	defer pinger.Stop()

	ch := sub.Chan()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if engine != nil && !eventVisible(engine, clusterID, ev) {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		case <-pinger.C:
			if err := conn.WriteControl(
				websocket.PingMessage,
				[]byte{},
				time.Now().Add(5*time.Second),
			); err != nil {
				return
			}
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// eventResources maps a feed event's kind to the permission resource that shows it.
// ReplicaSet events (scaling, pod creation) belong to the Deployment tab.
var eventResources = map[string]string{
	"Pod": "pods", "Deployment": "deployments", "ReplicaSet": "deployments", "DaemonSet": "daemonsets",
	"StatefulSet": "statefulsets", "HorizontalPodAutoscaler": "hpas", "Service": "services",
	"ConfigMap": "configmaps", "Ingress": "ingresses", "CronJob": "cronjobs", "Job": "jobs",
}

// eventVisible applies the Dashboard's rule to the live feed for a non-admin: an object's
// change, or a Kubernetes Event about it, shows only where the user may list that kind.
// A Namespace shows when the user has any grant in it; nodes and other cluster-scoped or
// unknown kinds never do.
func eventVisible(engine *rbac.Engine, clusterID int, ev kube.ResourceEvent) bool {
	kind := ev.Kind
	if ev.Verb == "event" {
		kind = ev.InvolvedKind
	}
	if kind == "Namespace" {
		name := ev.Name
		if ev.Verb == "event" {
			name = ev.InvolvedName
		}
		for _, ns := range engine.AllowedNamespaces(clusterID) {
			if ns == name {
				return true
			}
		}
		return false
	}
	resource, ok := eventResources[kind]
	return ok && ev.Namespace != "" && engine.Can(clusterID, ev.Namespace, resource, "list")
}
