package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// refreshHeader marks the list requests the UI sends on its own every few
// seconds. They are not audited: the list the user opened already was, and
// the HTTP request log still shows every request.
const refreshHeader = "X-OpenConsole-Refresh"

// auditEvent records e for request r. It fills in the acting user (from the
// token, unless set), the request id, source IP, user agent and the user's
// account source and, for Kubernetes resources, the request's cluster when
// the caller set none. Everything else (cluster of non-Kubernetes targets,
// details) is the caller's. The write happens in the background.
func (s *Server) auditEvent(r *http.Request, e models.AuditLog) {
	if r.Header.Get(refreshHeader) == "auto" && (e.Verb == audit.VerbList || e.Verb == audit.VerbGet) {
		return
	}
	userID := 0
	if claims, ok := auth.FromContext(r.Context()); ok {
		userID = claims.UserID
		if e.User == "" {
			e.User = claims.Username
		}
	}
	e.RequestID = logpkg.RequestIDFrom(r.Context())
	e.SourceIP = clientIP(r)
	e.UserAgent = r.UserAgent()
	if e.Cluster == "" && audit.IsKubeKind(e.ResourceType) {
		ci := clusterFrom(r.Context())
		e.Cluster, e.ClusterID = ci.Name, ci.ID
	}
	go func() {
		ctx := context.Background()
		if e.AuthSource == "" && userID > 0 {
			if u, err := s.store.GetUserByID(ctx, userID); err == nil {
				e.AuthSource = u.AuthSource
			}
		}
		s.audit.Record(ctx, e)
	}()
}

// auditRead records a successful read (list / get / logs) of a Kubernetes
// resource; resource is the RBAC name ("deployments"), name "*" for a list.
func (s *Server) auditRead(r *http.Request, verb, resource, namespace, name string) {
	s.auditEvent(r, models.AuditLog{
		Verb:         verb,
		ResourceType: audit.Kind(resource),
		Namespace:    namespace,
		ResourceName: name,
	})
}

// auditReadDenied records a read refused by requirePermission.
func (s *Server) auditReadDenied(r *http.Request, resource, verb, reason string) {
	name := chi.URLParam(r, "name")
	if name == "" {
		name = "*"
	}
	s.auditEvent(r, models.AuditLog{
		Verb:         verb,
		Outcome:      audit.Denied,
		Reason:       reason,
		ResourceType: audit.Kind(resource),
		Namespace:    chi.URLParam(r, "namespace"),
		ResourceName: name,
	})
}

// Reasons for denied and failed outcomes.
const (
	reasonForbidden       = "forbidden"
	reasonFeatureDisabled = "feature_disabled"
	reasonAdminOnly       = "admin_only"
	reasonRateLimited     = "rate_limited"
)

// failReason classifies an error for a failed outcome; the message itself
// goes into the "error" detail.
func failReason(err error) string {
	var status apierrors.APIStatus
	switch {
	case err == nil:
		return ""
	case apierrors.IsForbidden(err):
		return "k8s_forbidden"
	case apierrors.IsNotFound(err):
		return "not_found"
	case apierrors.IsConflict(err):
		return "conflict"
	case apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
		return "invalid"
	case errors.As(err, &status):
		return "k8s_error"
	}
	return "error"
}

// failDetails returns d with the error message added.
func failDetails(err error, d audit.D) audit.D {
	if d == nil {
		d = audit.D{}
	}
	if err != nil {
		d["error"] = err.Error()
	}
	return d
}

// recordLoginAudit records a sign-in attempt. user is the name typed (or
// the account's), since a failed attempt has no token.
func (s *Server) recordLoginAudit(r *http.Request, user, outcome, reason string, details audit.D) {
	authSource := ""
	if m, ok := details["login_method"].(string); ok {
		authSource = m
	}
	s.auditEvent(r, models.AuditLog{
		User:         user,
		Verb:         audit.VerbLogin,
		Outcome:      outcome,
		Reason:       reason,
		ResourceType: audit.KindUser,
		ResourceName: user,
		AuthSource:   authSource,
		Details:      details,
	})
}

// recordSettingsUpdate records a change to an admin setting (ldap,
// azure_ad, session, logo).
func (s *Server) recordSettingsUpdate(r *http.Request, name string, details audit.D) {
	s.auditEvent(r, models.AuditLog{
		Verb:         audit.VerbUpdate,
		ResourceType: audit.KindSettings,
		ResourceName: name,
		Details:      details,
	})
}

// recordPermissionAudit records a grant added to or removed from a role. The
// event's cluster and namespace are the grant's, not the admin's current
// cluster; a grant for all clusters has no cluster.
func (s *Server) recordPermissionAudit(r *http.Request, verb string, p models.NamespacePermission) {
	d := audit.D{"role": s.roleNameByID(r, p.RoleID)}
	if p.Resource != "" {
		d["grant"] = p.Resource + ":" + p.Action
	}
	if p.ID > 0 {
		d["id"] = p.ID
	}
	s.auditEvent(r, models.AuditLog{
		Verb:         verb,
		ResourceType: audit.KindPermission,
		ResourceName: d["role"].(string),
		Namespace:    p.Namespace,
		Cluster:      p.ClusterName,
		ClusterID:    p.ClusterID,
		Details:      d,
	})
}

func (s *Server) userNameByID(r *http.Request, id int) string {
	if u, err := s.store.GetUserByID(r.Context(), id); err == nil {
		return u.Username
	}
	return "id:" + strconv.Itoa(id)
}

func (s *Server) groupNameByID(r *http.Request, id int) string {
	if names, err := s.groupNames(r); err == nil && names[id] != "" {
		return names[id]
	}
	return "id:" + strconv.Itoa(id)
}

func (s *Server) roleNameByID(r *http.Request, id int) string {
	if roles, err := s.store.ListRoles(r.Context()); err == nil {
		for _, role := range roles {
			if role.ID == id {
				return role.Name
			}
		}
	}
	return "id:" + strconv.Itoa(id)
}
