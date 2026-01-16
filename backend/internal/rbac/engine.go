package rbac

import (
	"strings"

	"k8s-dashboard/backend/internal/models"
)

type Engine struct {
	permissions []models.NamespacePermission
}

func New(permissions []models.NamespacePermission) *Engine {
	return &Engine{permissions: permissions}
}

func (e *Engine) AllowedNamespaces() []string {
	seen := make(map[string]struct{})
	for _, perm := range e.permissions {
		seen[perm.Namespace] = struct{}{}
	}
	var namespaces []string
	for namespace := range seen {
		namespaces = append(namespaces, namespace)
	}
	return namespaces
}

func (e *Engine) Can(namespace, resource, action string) bool {
	for _, perm := range e.permissions {
		if strings.EqualFold(perm.Namespace, namespace) &&
			strings.EqualFold(perm.Resource, resource) &&
			strings.EqualFold(perm.Action, action) {
			return true
		}
	}
	return false
}

func (e *Engine) AllowedResources(namespace string) map[string][]string {
	result := make(map[string][]string)
	for _, perm := range e.permissions {
		if strings.EqualFold(perm.Namespace, namespace) {
			result[perm.Resource] = append(result[perm.Resource], perm.Action)
		}
	}
	return result
}
