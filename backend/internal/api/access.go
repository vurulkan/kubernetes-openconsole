package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"k8s-dashboard/backend/internal/auth"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
	"k8s-dashboard/backend/internal/rbac"
)

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.isAdminRequest(r); !ok {
			writeError(w, http.StatusForbidden, reasonAdminOnly)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAdminRequest is the one admin check: an active admin who has changed the
// initial password, on a web session or with an API key that has the admin
// scope. Losing the admin flag takes effect on the next call, key or not.
func (s *Server) isAdminRequest(r *http.Request) (*models.User, bool) {
	user, ok := s.userForRequest(r)
	if !ok || !user.IsAdmin || user.MustChangePassword {
		return user, false
	}
	if k := apiKeyFrom(r.Context()); k != nil && (!k.AdminScope || !rbac.AdminScopeAllowed(user.APIAccessOverride)) {
		return user, false
	}
	return user, true
}

// engineForRequest fails for a non-admin who must change the password: callers answer 403,
// never 401, because the UI signs out on 401. (Admins kept reading before
// changing it; their admin screens check it in isAdminRequest.)
func (s *Server) engineForRequest(r *http.Request) (*rbac.Engine, bool) {
	user, ok := s.userForRequest(r)
	if !ok || (user.MustChangePassword && !user.IsAdmin) {
		return nil, false
	}
	engine, err := s.accessFor(r.Context(), user)
	return engine, err == nil
}

// accessFor is the single source of what user may do on this request: the
// web access, or with an API key on ctx the key access narrowed to the key's scope.
func (s *Server) accessFor(ctx context.Context, user *models.User) (*rbac.Engine, error) {
	k := apiKeyScopeFrom(ctx)
	if k == nil {
		return s.webAccess(ctx, user)
	}
	engine, err := s.keyAccess(ctx, user)
	if err != nil {
		return nil, err
	}
	return engine.WithKey(k), nil
}

// webAccess: an admin holds every grant, anyone else their roles' grants.
func (s *Server) webAccess(ctx context.Context, user *models.User) (*rbac.Engine, error) {
	if user.IsAdmin {
		return rbac.NewAdmin(), nil
	}
	perms, err := s.store.ListPermissionsByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return rbac.New(perms), nil
}

// keyAccess is the most user's API keys may reach: the web access through the
// admin's API access policy (role modes, the user's override). accessFor and
// ceilingFor both use it, so the key form offers exactly what a key gets.
func (s *Server) keyAccess(ctx context.Context, user *models.User) (*rbac.Engine, error) {
	if user.IsAdmin {
		return rbac.NewAdminKeys(user.APIAccessOverride), nil
	}
	perms, err := s.store.ListPermissionsByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return rbac.New(rbac.KeyCeiling(perms, user.APIAccessOverride)), nil
}

// denyReason names a refusal: api_access_policy when the key lists the grant
// and its owner holds it on the web, so only the admin's policy stands in
// the way; forbidden otherwise.
func (s *Server) denyReason(ctx context.Context, namespace, resource, action string) string {
	c, ok := auth.FromContext(ctx)
	if !ok || c.APIKey == nil || !featureAllows(resource, action) {
		return reasonForbidden
	}
	user, err := s.store.GetUserByID(ctx, c.UserID)
	if err != nil {
		return reasonForbidden
	}
	web, err := s.webAccess(ctx, user)
	if err == nil && web.WithKey(&c.APIKey.APIKeyScope).Can(clusterIDFrom(ctx), namespace, resource, action) {
		return reasonAPIAccessPolicy
	}
	return reasonForbidden
}

func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, resource, action string) (string, bool) {
	if _, ok := s.userForRequest(r); !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return "", false
	}
	namespace := chi.URLParam(r, "namespace")
	if !featureAllows(resource, action) {
		s.auditReadDenied(r, resource, action, reasonFeatureDisabled)
		writeError(w, http.StatusForbidden, reasonFeatureDisabled)
		return "", false
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		s.auditReadDenied(r, resource, action, reasonForbidden)
		writeError(w, http.StatusForbidden, reasonForbidden)
		return "", false
	}
	if !engine.Can(clusterIDFrom(r.Context()), namespace, resource, action) {
		reason := s.denyReason(r.Context(), namespace, resource, action)
		s.auditReadDenied(r, resource, action, reason)
		writeError(w, http.StatusForbidden, reason)
		return "", false
	}
	return namespace, true
}

// can is the permission check of handlers that don't go through
// requirePermission (sockets, reveal, apply, actions). Like userForRequest and
// engineForRequest, it refuses a disabled account and a non-admin who must
// still change the password, so neither can keep using a session it holds.
func (s *Server) can(ctx context.Context, userID int, namespace, resource, action string) bool {
	if !featureAllows(resource, action) {
		return false
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		logPermissionError(ctx, err)
		return false
	}
	if !user.IsActive || (user.MustChangePassword && !user.IsAdmin) {
		return false
	}
	engine, err := s.accessFor(ctx, user)
	if err != nil {
		logPermissionError(ctx, err)
		return false
	}
	return engine.Can(clusterIDFrom(ctx), namespace, resource, action)
}

// logPermissionError: a permission check that could not read the database
// refuses (and the caller audits a denial), so the cause is logged here.
func logPermissionError(ctx context.Context, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	slog.Error("permission check failed", slog.Any("error", err), slog.String("request_id", logpkg.RequestIDFrom(ctx)))
}

func (s *Server) userForRequest(r *http.Request) (*models.User, bool) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return nil, false
	}
	user, err := s.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil || !user.IsActive {
		return nil, false
	}
	return user, true
}

func (s *Server) allowLogStream(userID int) bool {
	s.logLimiterMu.Lock()
	defer s.logLimiterMu.Unlock()
	limiter, ok := s.logLimiters[userID]
	if !ok {
		// Loose enough for flipping container / live / previous in the log viewer;
		// it still stops a client from opening streams in a tight loop.
		limiter = rate.NewLimiter(rate.Every(time.Second), 10)
		s.logLimiters[userID] = limiter
	}
	return limiter.Allow()
}
