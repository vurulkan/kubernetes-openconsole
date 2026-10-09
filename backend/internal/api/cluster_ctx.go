package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
)

// Every user works on the cluster they picked in the header switcher
// (users.active_cluster_id). Users who never picked one — or whose pick is
// gone or no longer allowed — get the default cluster (clusters.is_active,
// set by an admin). clusterMiddleware resolves that once per request and
// attaches the cluster's Manager, so handlers and ResourceClient act on the
// caller's cluster rather than a process-wide one.

type clusterInfo struct {
	ID   int
	Name string
}

type clusterCtxKey struct{}

func clusterFrom(ctx context.Context) clusterInfo {
	ci, _ := ctx.Value(clusterCtxKey{}).(clusterInfo)
	return ci
}

// clusterIDFrom is the cluster id permission checks match against (0 when
// no cluster is configured; grants then match as wildcards).
func clusterIDFrom(ctx context.Context) int {
	return clusterFrom(ctx).ID
}

// kubeFor returns the request's cluster Manager; without one, a Manager with
// no client, so callers get their usual "not ready" path.
func kubeFor(r *http.Request) *kube.Manager {
	return kube.ForContext(r.Context())
}

func (s *Server) clusterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.FromContext(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), claims.UserID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		ci := s.resolveCluster(r.Context(), user)
		metricsRecordClusterRequest(ci.Name)
		ctx := context.WithValue(r.Context(), clusterCtxKey{}, ci)
		ctx = context.WithValue(ctx, logpkg.ClusterKey, ci.Name)
		if ci.ID > 0 {
			m, err := s.clusters.Get(ctx, ci.ID)
			if err != nil {
				slog.Warn("cluster unavailable",
					slog.Int("cluster_id", ci.ID),
					slog.String("cluster", ci.Name),
					slog.Any("error", err),
					slog.String("request_id", logpkg.RequestIDFrom(ctx)),
				)
			} else {
				ctx = kube.WithManager(ctx, m)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveCluster picks the user's cluster: their own valid selection, else
// the default cluster.
func (s *Server) resolveCluster(ctx context.Context, user *models.User) clusterInfo {
	if id := user.ActiveClusterID; id > 0 {
		if name, err := s.store.GetClusterName(ctx, id); err == nil && s.canUseCluster(ctx, user, id) {
			return clusterInfo{ID: id, Name: name}
		}
	}
	id := s.DefaultClusterID()
	if id == 0 {
		return clusterInfo{}
	}
	name, err := s.store.GetClusterName(ctx, id)
	if err != nil {
		return clusterInfo{}
	}
	return clusterInfo{ID: id, Name: name}
}

// canUseCluster: admins can use every cluster; other users any cluster that
// at least one of their grants covers (a grant for that cluster or for all
// clusters).
func (s *Server) canUseCluster(ctx context.Context, user *models.User, clusterID int) bool {
	if user.IsAdmin {
		return true
	}
	perms, err := s.store.ListPermissionsByUser(ctx, user.ID)
	if err != nil {
		return false
	}
	return rbac.New(perms).CoversCluster(clusterID)
}

// handleSelectCluster stores the caller's cluster choice. Body
// {"clusterId": N}; 0 goes back to the default cluster.
func (s *Server) handleSelectCluster(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		ClusterID int `json:"clusterId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClusterID < 0 {
		writeError(w, http.StatusBadRequest, "clusterId is required")
		return
	}
	name := "default"
	if body.ClusterID > 0 {
		n, err := s.store.GetClusterName(r.Context(), body.ClusterID)
		if err != nil {
			writeError(w, http.StatusNotFound, "cluster not found")
			return
		}
		if !s.canUseCluster(r.Context(), user, body.ClusterID) {
			s.recordClusterSelectAudit(r, user.Username, n, "denied")
			writeError(w, http.StatusForbidden, "you have no permissions on this cluster")
			return
		}
		// Connect now so a broken cluster fails here, not on the next page.
		if _, err := s.clusters.Get(r.Context(), body.ClusterID); err != nil {
			s.recordClusterSelectAudit(r, user.Username, n, "failed")
			writeError(w, http.StatusBadGateway, "cannot connect to cluster: "+err.Error())
			return
		}
		name = n
	}
	if err := s.store.SetUserActiveCluster(r.Context(), user.ID, body.ClusterID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save selection")
		return
	}
	s.recordClusterSelectAudit(r, user.Username, name, "success")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "clusterId": body.ClusterID, "name": name})
}

func (s *Server) recordClusterSelectAudit(r *http.Request, user, cluster, outcome string) {
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         user,
		Action:       "cluster.select." + outcome,
		Namespace:    "-",
		ResourceType: "cluster",
		ResourceName: cluster,
		Cluster:      cluster,
	})
}

// DefaultClusterID is the cluster users get until they pick one (0 = none).
func (s *Server) DefaultClusterID() int {
	return int(s.defaultClusterID.Load())
}

// requestIDOf returns the request's correlation id (set by
// requestIDMiddleware).
func requestIDOf(r *http.Request) string {
	return logpkg.RequestIDFrom(r.Context())
}

// clusterStatus maps every configured cluster's name to whether a live
// connection exists (for /metrics).
func (s *Server) clusterStatus() map[string]bool {
	out := map[string]bool{}
	clusters, err := s.store.ListClusters(context.Background())
	if err != nil {
		return out
	}
	for _, c := range clusters {
		out[c.Name] = s.clusters.Ready(c.ID)
	}
	return out
}
