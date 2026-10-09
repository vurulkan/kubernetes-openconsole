package kube

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"k8s-dashboard/backend/internal/models"
)

// Registry holds one Manager (client + informer cache) per configured
// cluster, created on first use. Each user works against the cluster they
// selected, so several clusters can be live at once; each costs one informer
// cache, and only clusters someone actually uses are started.
type Registry struct {
	load func(ctx context.Context, clusterID int) (models.KubeCredentials, error)

	mu       sync.Mutex
	managers map[int]*Manager
}

// NewRegistry takes a loader that returns the stored credentials for a
// cluster id (the store, in production).
func NewRegistry(load func(ctx context.Context, clusterID int) (models.KubeCredentials, error)) *Registry {
	return &Registry{load: load, managers: make(map[int]*Manager)}
}

// Get returns the cluster's Manager, connecting on first use. The informer
// cache warms up in the background; until it has synced, reads fall back to
// direct API calls.
func (r *Registry) Get(ctx context.Context, clusterID int) (*Manager, error) {
	if clusterID <= 0 {
		return nil, fmt.Errorf("no cluster selected")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.managers[clusterID]; ok {
		return m, nil
	}
	if r.load == nil {
		return nil, fmt.Errorf("cluster %d not available", clusterID)
	}
	creds, err := r.load(ctx, clusterID)
	if err != nil {
		return nil, fmt.Errorf("load cluster %d: %w", clusterID, err)
	}
	m := NewManager()
	if err := m.ApplyCredentials(creds); err != nil {
		return nil, fmt.Errorf("connect cluster %d: %w", clusterID, err)
	}
	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	r.managers[clusterID] = m
	slog.Info("cluster connected", slog.Int("cluster_id", clusterID))
	return m, nil
}

// Put installs a ready Manager for a cluster id (tests, or a manager built
// elsewhere).
func (r *Registry) Put(clusterID int, m *Manager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.managers[clusterID]; ok && old != m {
		old.Stop()
	}
	r.managers[clusterID] = m
}

// Invalidate stops and forgets a cluster's Manager; the next Get reconnects
// with the stored credentials. Call it after a cluster is updated or deleted.
func (r *Registry) Invalidate(clusterID int) {
	r.mu.Lock()
	m, ok := r.managers[clusterID]
	delete(r.managers, clusterID)
	r.mu.Unlock()
	if ok {
		m.Stop()
	}
}

// Ready reports whether the cluster's Manager exists and is connected,
// without connecting it.
func (r *Registry) Ready(clusterID int) bool {
	r.mu.Lock()
	m, ok := r.managers[clusterID]
	r.mu.Unlock()
	return ok && m.Ready()
}

// Connected returns the ids of clusters with a live Manager.
func (r *Registry) Connected() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]int, 0, len(r.managers))
	for id := range r.managers {
		ids = append(ids, id)
	}
	return ids
}

type managerCtxKey struct{}

// WithManager attaches the request's cluster Manager to ctx; ResourceClient
// methods use it instead of their default manager.
func WithManager(ctx context.Context, m *Manager) context.Context {
	return context.WithValue(ctx, managerCtxKey{}, m)
}

// ForContext returns the request's Manager, or an empty one (no client, not
// ready) when the request has no cluster.
func ForContext(ctx context.Context) *Manager {
	if m := ManagerFrom(ctx); m != nil {
		return m
	}
	return noCluster
}

// ManagerFrom returns the Manager attached by WithManager, or nil.
func ManagerFrom(ctx context.Context) *Manager {
	m, _ := ctx.Value(managerCtxKey{}).(*Manager)
	return m
}
