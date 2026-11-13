package rbac

import (
	"slices"
	"strings"

	"k8s-dashboard/backend/internal/models"
)

// API access modes: what a role's grants give its holders' API keys, and the
// per-user override ("" = by roles) that replaces the role modes.
const (
	AccessOff      = "off"
	AccessSafeRead = "safe_read"
	AccessFull     = "full"
)

// ValidMode reports whether m is a role mode (the override also takes "").
func ValidMode(m string) bool { return m == AccessOff || m == AccessSafeRead || m == AccessFull }

// SafeRead is the one definition of "safe read-only": list / get / logs,
// no ConfigMaps or Secrets (their data can hold credentials); so no exec,
// edit, scale, restart or reveal. The API key template uses it too.
func SafeRead(resource, action string) bool {
	r := strings.ToLower(resource)
	return slices.Contains([]string{"list", "get", "logs"}, strings.ToLower(action)) && r != "configmaps" && r != "secrets"
}

// SafeReadGrants lists the catalog's safe read-only grants ("pods:list").
func SafeReadGrants() []string {
	out := []string{}
	for _, c := range Catalog {
		for _, a := range c.Actions {
			if SafeRead(c.Resource, a) {
				out = append(out, c.Resource+":"+a)
			}
		}
	}
	return out
}

// Allows reports whether mode lets an API key hold resource:action. An
// unknown mode allows nothing.
func Allows(mode, resource, action string) bool {
	switch mode {
	case AccessFull:
		return true
	case AccessSafeRead:
		return SafeRead(resource, action)
	}
	return false
}

// KeyCeiling returns the grants of a non-admin's API keys: each of perms
// through its role's mode, or every one through override when it is set.
// It never adds a grant, so "full" stays within the user's web access.
func KeyCeiling(perms []models.NamespacePermission, override string) []models.NamespacePermission {
	out := []models.NamespacePermission{}
	for _, p := range perms {
		mode := p.RoleAPIAccess
		if override != "" {
			mode = override
		}
		if Allows(mode, p.Resource, p.Action) {
			out = append(out, p)
		}
	}
	return out
}

// AdminScopeAllowed: an admin's key may hold the Admin API scope only while
// the admin's override leaves keys every grant.
func AdminScopeAllowed(override string) bool { return override == "" || override == AccessFull }
