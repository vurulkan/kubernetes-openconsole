package rbac

import (
	"strings"

	"k8s-dashboard/backend/internal/models"
)

// Engine evaluates application-level permissions. All methods are cluster-aware:
// a permission row with ClusterID == 0 is a wildcard that matches any cluster
// (this is also how pre-M4-C1-phase-2 rows migrate — they have NULL in SQL,
// stored as 0 in Go, which means "all clusters" by design).
type Engine struct {
	permissions []models.NamespacePermission
}

func New(permissions []models.NamespacePermission) *Engine {
	return &Engine{permissions: permissions}
}

// matchesCluster returns true when a permission row applies to the given
// activeClusterID. ClusterID == 0 on either side means wildcard.
func matchesCluster(perm models.NamespacePermission, activeClusterID int) bool {
	if perm.ClusterID == 0 || activeClusterID == 0 {
		return true
	}
	return perm.ClusterID == activeClusterID
}

// AllowedNamespaces returns namespaces the caller may see on the given
// cluster. A zero cluster id returns the union across all clusters, which is
// used only when no cluster is active (empty dashboard state).
func (e *Engine) AllowedNamespaces(clusterID int) []string {
	seen := make(map[string]struct{})
	for _, perm := range e.permissions {
		if !matchesCluster(perm, clusterID) {
			continue
		}
		seen[perm.Namespace] = struct{}{}
	}
	namespaces := make([]string, 0, len(seen))
	for namespace := range seen {
		namespaces = append(namespaces, namespace)
	}
	return namespaces
}

// Can returns true when at least one permission row matches the full tuple.
func (e *Engine) Can(clusterID int, namespace, resource, action string) bool {
	for _, perm := range e.permissions {
		if !matchesCluster(perm, clusterID) {
			continue
		}
		if strings.EqualFold(perm.Namespace, namespace) &&
			strings.EqualFold(perm.Resource, resource) &&
			strings.EqualFold(perm.Action, action) {
			return true
		}
	}
	return false
}

// AllowedResources groups a user's permissions on (clusterID, namespace) into
// resource → [actions], which drives the Dashboard's tab visibility.
func (e *Engine) AllowedResources(clusterID int, namespace string) map[string][]string {
	result := make(map[string][]string)
	for _, perm := range e.permissions {
		if !matchesCluster(perm, clusterID) {
			continue
		}
		if strings.EqualFold(perm.Namespace, namespace) {
			result[perm.Resource] = append(result[perm.Resource], perm.Action)
		}
	}
	return result
}
