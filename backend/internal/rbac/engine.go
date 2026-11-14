package rbac

import (
	"slices"
	"strings"

	"k8s-dashboard/backend/internal/models"
)

// Catalog is every resource → action pair the backend checks, in display
// order. Admins hold all of it; the Role Permissions and API key matrices in
// the UI show the same list (frontend components/PermissionMatrix.tsx).
var Catalog = []struct {
	Resource string
	Actions  []string
}{
	{"pods", []string{"list", "get", "logs", "exec", "edit"}},
	{"deployments", []string{"list", "get", "restart", "scale", "edit"}},
	{"daemonsets", []string{"list", "get", "edit"}},
	{"statefulsets", []string{"list", "get", "scale", "edit"}},
	{"hpas", []string{"list", "get", "edit"}},
	{"services", []string{"list", "get", "edit"}},
	{"configmaps", []string{"list", "get", "edit"}},
	{"secrets", []string{"list", "get", "reveal", "edit"}},
	{"ingresses", []string{"list", "get", "edit"}},
	{"cronjobs", []string{"list", "get", "edit", "trigger"}},
	{"jobs", []string{"list", "get", "edit"}},
}

// Engine evaluates application-level permissions. All methods are cluster-aware:
// a permission row with ClusterID == 0 is a wildcard that matches any cluster
// (this is also how pre-M4-C1-phase-2 rows migrate — they have NULL in SQL,
// stored as 0 in Go, which means "all clusters" by design).
//
// An admin engine holds every grant in every namespace. WithKey narrows
// either kind to an API key: what the key lists ∩ what the user holds now.
type Engine struct {
	permissions []models.NamespacePermission
	admin       bool
	// adminMode limits an admin engine to an API access mode ("" = no limit).
	adminMode string
	key       *models.APIKeyScope
}

func New(permissions []models.NamespacePermission) *Engine {
	return &Engine{permissions: permissions}
}

// NewAdmin returns the engine of an admin: every grant everywhere.
func NewAdmin() *Engine { return &Engine{admin: true} }

// NewAdminKeys returns what an admin's API keys may reach: every grant
// everywhere, limited by the admin's override (role modes do not apply).
func NewAdminKeys(override string) *Engine {
	return &Engine{admin: true, adminMode: AdminKeyMode(override)}
}

// AdminKeyMode is the mode of an admin's keys: the override, else full.
func AdminKeyMode(override string) string {
	if override == "" {
		return AccessFull
	}
	return override
}

// WithKey narrows e to an API key's scope (nil = no key, e unchanged).
func (e *Engine) WithKey(k *models.APIKeyScope) *Engine {
	if k == nil {
		return e
	}
	return &Engine{permissions: Restrict(e.permissions, k), admin: e.admin, adminMode: e.adminMode, key: k}
}

// adminAllows: what an admin engine's mode lets through.
func (e *Engine) adminAllows(resource, action string) bool {
	return e.adminMode == "" || Allows(e.adminMode, resource, action)
}

// Restrict returns the grants of perms the key k also lists. A grant for
// every cluster used by a key for one cluster becomes a grant for that cluster.
func Restrict(perms []models.NamespacePermission, k *models.APIKeyScope) []models.NamespacePermission {
	out := []models.NamespacePermission{}
	for _, p := range perms {
		if !keyHasNamespace(k, p.Namespace) || !keyHasGrant(k, p.Resource, p.Action) {
			continue
		}
		for _, c := range k.Clusters {
			q := p
			switch {
			case c == 0:
			case q.ClusterID == 0:
				q.ClusterID = c
			case q.ClusterID != c:
				continue
			}
			out = append(out, q)
		}
	}
	return out
}

func keyHasCluster(k *models.APIKeyScope, clusterID int) bool {
	return clusterID == 0 || slices.ContainsFunc(k.Clusters, func(c int) bool { return c == 0 || c == clusterID })
}

func keyHasNamespace(k *models.APIKeyScope, namespace string) bool {
	return k.AllNamespaces || slices.ContainsFunc(k.Namespaces, func(n string) bool { return strings.EqualFold(n, namespace) })
}

func keyHasGrant(k *models.APIKeyScope, resource, action string) bool {
	return slices.ContainsFunc(k.Grants, func(g string) bool { return strings.EqualFold(g, resource+":"+action) })
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
// used only when no cluster is active (empty dashboard state). An admin's
// namespaces cannot be listed here (every namespace): use SeesNamespace.
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

// SeesNamespace reports whether the caller has any grant in namespace.
func (e *Engine) SeesNamespace(clusterID int, namespace string) bool {
	if e.admin {
		return e.adminMode != AccessOff && (e.key == nil || (keyHasCluster(e.key, clusterID) && keyHasNamespace(e.key, namespace)))
	}
	return slices.Contains(e.AllowedNamespaces(clusterID), namespace)
}

// Can returns true when at least one permission row matches the full tuple.
func (e *Engine) Can(clusterID int, namespace, resource, action string) bool {
	if e.admin {
		return e.adminAllows(resource, action) &&
			(e.key == nil || (keyHasCluster(e.key, clusterID) && keyHasNamespace(e.key, namespace) && keyHasGrant(e.key, resource, action)))
	}
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
	if e.admin {
		for _, c := range Catalog {
			for _, a := range c.Actions {
				if e.Can(clusterID, namespace, c.Resource, a) {
					result[c.Resource] = append(result[c.Resource], a)
				}
			}
		}
		return result
	}
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

// CoversCluster reports whether any grant applies to the cluster (a grant for
// that cluster, or one for all clusters).
func (e *Engine) CoversCluster(clusterID int) bool {
	if e.admin {
		return e.adminMode != AccessOff && (e.key == nil || keyHasCluster(e.key, clusterID))
	}
	for _, perm := range e.permissions {
		if perm.ClusterID == 0 || perm.ClusterID == clusterID {
			return true
		}
	}
	return false
}
