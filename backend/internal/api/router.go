package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	"sigs.k8s.io/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/store"
)

type Server struct {
	store      *store.Store
	audit      *audit.Logger
	kube       *kube.Manager
	resources  *kube.ResourceClient
	jwtKey     []byte
	logLimiters map[int]*rate.Limiter
	logLimiterMu sync.Mutex
	staticDir  string
	dataDir    string
	timezone   *time.Location
	// Active cluster id — cached from the clusters.is_active row and refreshed
	// on activate/deactivate. 0 means "no active cluster", in which case
	// permission checks fall back to wildcard matching.
	activeClusterID atomic.Int64
}

func NewServer(store *store.Store, auditLogger *audit.Logger, kubeManager *kube.Manager, staticDir string, dataDir string, timeZone string) *Server {
	location, err := time.LoadLocation(timeZone)
	if err != nil {
		location = time.UTC
	}
	s := &Server{
		store:      store,
		audit:      auditLogger,
		kube:       kubeManager,
		resources:  kube.NewResourceClient(kubeManager),
		jwtKey:     store.SigningKey(),
		logLimiters: make(map[int]*rate.Limiter),
		staticDir:  staticDir,
		dataDir:    dataDir,
		timezone:   location,
	}
	// Seed the active cluster id from whatever row is currently is_active.
	// Called sync so permission checks on early requests see a stable value.
	if cluster, err := store.GetActiveCluster(context.Background()); err == nil && cluster != nil {
		s.activeClusterID.Store(int64(cluster.ID))
	}
	return s
}

// ActiveClusterID returns the currently-active cluster id, or 0 when none is
// set (fresh install or after a deactivate). Permission checks treat 0 as
// "wildcard — any permission row applies".
func (s *Server) ActiveClusterID() int {
	return int(s.activeClusterID.Load())
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(corsMiddleware)
	r.Use(securityHeaders)
	r.Use(requestIDMiddleware)
	r.Use(recoverMiddleware)
	r.Use(requestLogger)

	// Liveness: just confirms the process is accepting requests.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live"))
	})
	// Readiness: DB handle usable + if a cluster is configured, it must be
	// ready. Returns 503 otherwise so Kubernetes rolls the pod out of service.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("db not reachable"))
			return
		}
		if creds, err := s.store.GetKubeCredentials(r.Context()); err == nil && creds.Active && !s.kube.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("cluster not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	// Prometheus-compatible metrics (unauthenticated — restrict at the network
	// layer / scrape via internal service).
	r.Get("/metrics", handleMetrics)

	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		r.Get("/azure/start", s.handleAzureStart)
		r.Get("/azure/callback", s.handleAzureCallback)
		r.Get("/providers", s.handleAuthProviders)
		r.With(auth.AuthMiddleware(s.jwtKey)).Get("/me", s.handleMe)
		r.With(auth.AuthMiddleware(s.jwtKey)).Post("/change-password", s.handleChangePassword)
	})

	r.Get("/api/customization/logo", s.handleGetLogo)

	r.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddleware(s.jwtKey))
		r.Get("/api/cluster/active", s.handleGetActiveCluster)
		r.Get("/api/clusters/public", s.handleListClustersPublic)
		r.Get("/api/namespaces", s.handleNamespaces)
		r.Get("/api/namespaces/{namespace}/permissions", s.handleNamespacePermissions)
		r.Get("/api/namespaces/{namespace}/pods", s.handlePods)
		r.Get("/api/namespaces/{namespace}/pods/{name}", s.handlePod)
		r.Get("/api/namespaces/{namespace}/pods/{name}/yaml", s.handlePodYAML)
		r.Get("/api/namespaces/{namespace}/pods/{name}/events", s.handlePodEvents)
		r.Get("/api/namespaces/{namespace}/deployments", s.handleDeployments)
		r.Get("/api/namespaces/{namespace}/deployments/{name}", s.handleDeployment)
		r.Get("/api/namespaces/{namespace}/deployments/{name}/yaml", s.handleDeploymentYAML)
		r.Get("/api/namespaces/{namespace}/deployments/{name}/events", s.handleDeploymentEvents)
		r.Post("/api/namespaces/{namespace}/deployments/{name}/restart", s.handleDeploymentRestart)
		r.Post("/api/namespaces/{namespace}/deployments/{name}/scale", s.handleDeploymentScale)
		r.Get("/api/namespaces/{namespace}/services", s.handleServices)
		r.Get("/api/namespaces/{namespace}/services/{name}", s.handleService)
		r.Get("/api/namespaces/{namespace}/services/{name}/yaml", s.handleServiceYAML)
		r.Get("/api/namespaces/{namespace}/configmaps", s.handleConfigMaps)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}", s.handleConfigMap)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}/yaml", s.handleConfigMapYAML)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}/data", s.handleConfigMapData)
		r.Get("/api/namespaces/{namespace}/ingresses", s.handleIngresses)
		r.Get("/api/namespaces/{namespace}/ingresses/{name}/yaml", s.handleIngressYAML)
		r.Get("/api/namespaces/{namespace}/cronjobs", s.handleCronJobs)
		r.Get("/api/namespaces/{namespace}/cronjobs/{name}/yaml", s.handleCronJobYAML)
		r.Get("/api/namespaces/{namespace}/jobs", s.handleJobs)
		r.Get("/api/namespaces/{namespace}/jobs/{name}/yaml", s.handleJobYAML)
		r.Get("/ws/namespaces/{namespace}/pods/{name}/logs", s.handlePodLogsWS)
		r.Get("/ws/namespaces/{namespace}/pods/{name}/exec", s.handlePodExecWS)
		r.Get("/ws/namespaces/{namespace}/deployments/{name}/logs", s.handleDeploymentLogsWS)
	})

	r.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddleware(s.jwtKey))
		r.Use(s.requireAdmin)
		r.Get("/api/admin/users", s.handleListUsers)
		r.Post("/api/admin/users", s.handleCreateUser)
		r.Put("/api/admin/users/{id}", s.handleUpdateUser)
		r.Delete("/api/admin/users/{id}", s.handleDeleteUser)
		r.Put("/api/admin/users/{id}/groups", s.handleSetUserGroups)
		r.Get("/api/admin/users/{id}/groups", s.handleGetUserGroups)
		
		r.Get("/api/admin/groups", s.handleListGroups)
		r.Post("/api/admin/groups", s.handleCreateGroup)
		r.Put("/api/admin/groups/{id}", s.handleUpdateGroup)
		r.Delete("/api/admin/groups/{id}", s.handleDeleteGroup)
		r.Put("/api/admin/groups/{id}/roles", s.handleSetGroupRoles)
		r.Get("/api/admin/groups/{id}/roles", s.handleGetGroupRoles)

		r.Get("/api/admin/roles", s.handleListRoles)
		r.Post("/api/admin/roles", s.handleCreateRole)
		r.Put("/api/admin/roles/{id}", s.handleUpdateRole)
		r.Delete("/api/admin/roles/{id}", s.handleDeleteRole)
		r.Get("/api/admin/roles/{id}/permissions", s.handleListRolePermissions)
		r.Post("/api/admin/roles/{id}/permissions", s.handleAddRolePermission)
		r.Delete("/api/admin/permissions/{id}", s.handleDeletePermission)

		r.Get("/api/admin/ldap", s.handleGetLDAP)
		r.Put("/api/admin/ldap", s.handleUpdateLDAP)
		r.Post("/api/admin/ldap/test", s.handleTestLDAP)
		r.Post("/api/admin/ldap/users/search", s.handleSearchLDAPUsers)
		r.Post("/api/admin/ldap/users/import", s.handleImportLDAPUsers)
		r.Get("/api/admin/azure-ad", s.handleGetAzureAD)
		r.Put("/api/admin/azure-ad", s.handleUpdateAzureAD)
		r.Post("/api/admin/azure-ad/test", s.handleTestAzureAD)

		r.Get("/api/admin/session", s.handleGetSession)
		r.Put("/api/admin/session", s.handleUpdateSession)

		r.Get("/api/admin/cluster", s.handleGetCluster)
		r.Post("/api/admin/cluster", s.handleUpdateCluster)

		// Multi-cluster CRUD (admin only). The legacy /api/admin/cluster
		// endpoint stays for backward compat; new UI uses these.
		r.Get("/api/admin/clusters", s.handleListClusters)
		r.Post("/api/admin/clusters", s.handleCreateCluster)
		r.Put("/api/admin/clusters/{id}", s.handleUpdateClusterByID)
		r.Delete("/api/admin/clusters/{id}", s.handleDeleteCluster)
		r.Post("/api/admin/clusters/{id}/activate", s.handleActivateCluster)
		r.Post("/api/admin/clusters/{id}/deactivate", s.handleDeactivateCluster)
		r.Put("/api/admin/cluster", s.handleUpdateCluster)
		r.Post("/api/admin/cluster/validate", s.handleValidateCluster)

		r.Get("/api/admin/audit-logs", s.handleAuditLogs)
		r.Get("/api/admin/audit-logs/export", s.handleAuditLogsExport)

		r.Post("/api/admin/customization/logo", s.handleUploadLogo)
		r.Delete("/api/admin/customization/logo", s.handleDeleteLogo)
	})

	if s.staticDir != "" {
		r.NotFound(s.serveSPA)
		r.MethodNotAllowed(s.serveSPA)
	}

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacker not supported")
	}
	return hijacker.Hijack()
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := r.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), logpkg.RequestIDKey, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logf is a thin shim preserving legacy printf-style call sites while routing
// output through slog. Prefer slog.LogAttrs with structured fields in new code.
func logf(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}

func logWarnf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func newRequestID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if idx := strings.Index(v, ","); idx > 0 {
			return strings.TrimSpace(v[:idx])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-Ip"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		duration := time.Since(start)

		level := slog.LevelInfo
		if recorder.status >= 500 {
			level = slog.LevelError
		} else if recorder.status >= 400 {
			level = slog.LevelWarn
		}

		slog.LogAttrs(r.Context(), level, "http.request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int64("duration_ms", duration.Milliseconds()),
			slog.String("remote_ip", clientIP(r)),
			slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
			slog.String("user_agent", r.UserAgent()),
		)
		metricsRecordRequest(recorder.status, duration.Milliseconds())
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.ErrorContext(r.Context(), "http.panic",
					slog.Any("error", err),
					slog.String("path", r.URL.Path),
					slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
				)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.staticDir, filepath.Clean(r.URL.Path))
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		http.ServeFile(w, r, path)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.userForRequest(r)
		if !ok || !user.IsAdmin {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if user.MustChangePassword {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recordAudit(r *http.Request, action, namespace, resourceType, resourceName string) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return
	}
	entry := models.AuditLog{
		User:         claims.Username,
		Action:       action,
		Namespace:    namespace,
		ResourceType: resourceType,
		ResourceName: resourceName,
	}
	go s.audit.Record(context.Background(), entry)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gateKey := clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(request.Username))
	if ok, retry := LoginGate().check(gateKey); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		go s.audit.Record(context.Background(), models.AuditLog{
			User:         request.Username,
			Action:       "login.locked",
			Namespace:    "-",
			ResourceType: "auth",
			ResourceName: "local",
		})
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), request.Username)
	if err != nil || !user.IsActive {
		LoginGate().recordFailure(gateKey)
		go s.audit.Record(context.Background(), models.AuditLog{
			User:         request.Username,
			Action:       "login.failed",
			Namespace:    "-",
			ResourceType: "auth",
			ResourceName: "unknown_user",
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	authenticated := false
	if err := auth.ComparePassword(user.PasswordHash, request.Password); err == nil {
		authenticated = true
	} else {
		cfg, cfgErr := s.store.GetLDAPConfig(r.Context())
		if cfgErr == nil && cfg.Enabled {
			ldapCfg := auth.LDAPConfig{
				Enabled: cfg.Enabled,
				URL: cfg.URL,
				Host: cfg.Host,
				Port: cfg.Port,
				UseSSL: cfg.UseSSL,
				StartTLS: cfg.StartTLS,
				SkipVerify: cfg.SkipVerify,
				TimeoutSeconds: cfg.TimeoutSeconds,
				BindDN: cfg.BindDN,
				BindPassword: cfg.BindPassword,
				UserBaseDN: cfg.UserBaseDN,
				UserBaseDNs: cfg.UserBaseDNs,
				UserFilter: cfg.UserFilter,
				UsernameAttribute: cfg.UsernameAttribute,
			}
			if err := auth.LDAPAuthenticate(ldapCfg, request.Username, request.Password); err == nil {
				authenticated = true
			}
		}
	}

	if !authenticated {
		LoginGate().recordFailure(gateKey)
		go s.audit.Record(context.Background(), models.AuditLog{
			User:         request.Username,
			Action:       "login.failed",
			Namespace:    "-",
			ResourceType: "auth",
			ResourceName: "bad_password",
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	LoginGate().recordSuccess(gateKey)
	s.issueTokenForUser(w, r, user)
}

func (s *Server) issueTokenForUser(w http.ResponseWriter, r *http.Request, user *models.User) {
	if user == nil || !user.IsActive {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	token, err := auth.GenerateToken(s.jwtKey, user.ID, user.Username, time.Duration(session.SessionMinutes)*time.Minute)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleAuthProviders(w http.ResponseWriter, r *http.Request) {
	azureEnabled := false
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err == nil && cfg.Enabled && cfg.ClientID != "" && cfg.TenantID != "" && cfg.RedirectURL != "" {
		azureEnabled = true
	}
	writeJSON(w, http.StatusOK, map[string]bool{"azureAdEnabled": azureEnabled})
}

func (s *Server) handleAzureStart(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil || !cfg.Enabled || cfg.ClientID == "" || cfg.TenantID == "" || cfg.RedirectURL == "" {
		writeError(w, http.StatusBadRequest, "azure ad is not configured")
		return
	}
	state := randomPassword()
	http.SetCookie(w, &http.Cookie{
		Name:     "azure_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	url, err := auth.AzureAuthorizeURL(ctx, auth.AzureADConfig{
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}, state)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to initialize azure login")
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleAzureCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("azure_oauth_state")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing oauth state")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "azure_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	if r.URL.Query().Get("state") == "" || stateCookie.Value != r.URL.Query().Get("state") {
		writeError(w, http.StatusBadRequest, "invalid oauth state")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing oauth code")
		return
	}
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil || !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "azure ad is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	username, err := auth.AzureExchangeCode(ctx, auth.AzureADConfig{
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}, code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "azure authentication failed")
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "failed to load user")
			return
		}
		randomHash, hashErr := auth.HashPassword(randomPassword())
		if hashErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to initialize user")
			return
		}
		userID, createErr := s.store.CreateUser(r.Context(), username, randomHash)
		if createErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to create user")
			return
		}
		user, err = s.store.GetUserByID(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load user")
			return
		}
	}
	if !user.IsActive {
		writeError(w, http.StatusForbidden, "user is disabled")
		return
	}

	session, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load session settings")
		return
	}
	token, err := auth.GenerateToken(s.jwtKey, user.ID, user.Username, time.Duration(session.SessionMinutes)*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	go s.audit.Record(context.Background(), models.AuditLog{
		User:         user.Username,
		Action:       "login.azure",
		Namespace:    "-",
		ResourceType: "auth",
		ResourceName: "azure_ad",
	})

	// The global securityHeaders middleware blocks inline scripts with CSP
	// script-src 'self'. This bootstrap page writes the token into
	// localStorage before redirecting, so we have to permit THIS inline
	// script. Give it a per-response nonce and override CSP for this
	// response only — same middleware check lets handler-set headers win.
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes[:])
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonce+"'; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src 'self' https://fonts.gstatic.com data:; "+
			"img-src 'self' data: blob:; "+
			"connect-src 'self' ws: wss:; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fmt.Sprintf(`<!doctype html><html><body><script nonce=%q>
try { localStorage.setItem('authToken', %q); } catch (e) {}
window.location.replace('/');
</script></body></html>`, nonce, token)))
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	perms, err := s.store.ListPermissionsByUser(r.Context(), user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	engine := rbac.New(perms)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":        user,
		"namespaces":  engine.AllowedNamespaces(s.ActiveClusterID()),
		"permissions": perms,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := auth.ComparePassword(user.PasswordHash, request.CurrentPassword); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hash, err := auth.HashPassword(request.NewPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), user.ID, hash, false); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "change_password", "-", "users", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	existing, err := s.resources.ListNamespaces(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if user.IsAdmin {
		var all []string
		for _, ns := range existing {
			all = append(all, ns.Name)
		}
		s.recordAudit(r, "list", "-", "namespaces", "*")
		writeJSON(w, http.StatusOK, map[string]interface{}{"namespaces": all})
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	allowed := engine.AllowedNamespaces(s.ActiveClusterID())
	allowedSet := make(map[string]struct{})
	for _, ns := range allowed {
		allowedSet[ns] = struct{}{}
	}
	var result []string
	for _, ns := range existing {
		if _, ok := allowedSet[ns.Name]; ok {
			result = append(result, ns.Name)
		}
	}
	s.recordAudit(r, "list", "-", "namespaces", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"namespaces": result})
}

func (s *Server) handleNamespacePermissions(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if user.IsAdmin {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"resources": map[string][]string{
				"pods":        {"list", "get", "logs", "exec"},
				"deployments": {"list", "get", "restart", "scale"},
				"services":    {"list", "get"},
				"configmaps":  {"list", "get"},
				"ingresses":   {"list", "get"},
				"cronjobs":    {"list", "get"},
				"jobs":        {"list", "get"},
			},
		})
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	permissions := engine.AllowedResources(s.ActiveClusterID(), namespace)
	if len(permissions) == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"resources": permissions})
}

func (s *Server) handlePods(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "list")
	if !ok {
		return
	}
	pods, err := s.resources.ListPods(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "pods", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": pods})
}

func (s *Server) handlePod(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	pod, err := s.resources.GetPod(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.recordAudit(r, "get", namespace, "pods", pod.Name)
	writeJSON(w, http.StatusOK, pod)
}

func (s *Server) handleDeployments(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListDeployments(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "deployments", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleDeployment(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetDeployment(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.recordAudit(r, "get", namespace, "deployments", item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "services", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListServices(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "services", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "services", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetService(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.recordAudit(r, "get", namespace, "services", item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleConfigMaps(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListConfigMaps(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "configmaps", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleConfigMap(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetConfigMap(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.recordAudit(r, "get", namespace, "configmaps", item.Name)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handlePodLogsWS(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		logWarnf("logs ws unauthorized")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	if !s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		logWarnf("logs ws forbidden user=%s ns=%s", claims.Username, namespace)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.allowLogStream(claims.UserID) {
		logWarnf("logs ws rate limited user=%s", claims.Username)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	s.recordAudit(r, "logs", namespace, "pods", chi.URLParam(r, "name"))

	client, ok := s.kube.Client()
	if !ok {
		logWarnf("logs ws client not ready")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logWarnf("logs ws upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	podName := chi.URLParam(r, "name")
	container := r.URL.Query().Get("container")
	tail := int64(100)
	if value := r.URL.Query().Get("tail"); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > 0 {
			tail = parsed
		}
	}
	logOptions := &models.PodLogOptions{Container: container, TailLines: tail}

	stream, err := client.CoreV1().Pods(namespace).GetLogs(podName, logOptions.ToKube()).Stream(r.Context())
	if err != nil {
		logWarnf("logs ws stream error: %v", err)
		_ = conn.WriteMessage(websocket.TextMessage, []byte("log stream unavailable"))
		return
	}
	defer stream.Close()

	buffer := make([]byte, 2048)
	for {
		count, err := stream.Read(buffer)
		if count > 0 {
			_ = conn.WriteMessage(websocket.TextMessage, buffer[:count])
		}
		if err != nil {
			break
		}
	}
}

func (s *Server) handlePodYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	pod, err := s.resources.GetPod(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pod.ManagedFields = nil
	data, err := yaml.Marshal(pod)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleDeploymentYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetDeployment(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleServiceYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "services", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetService(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleConfigMapYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetConfigMap(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleConfigMapData(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "configmaps", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetConfigMap(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": item.Data})
}

func (s *Server) handleIngresses(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "ingresses", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListIngresses(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "ingresses", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleCronJobs(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "cronjobs", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListCronJobs(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "cronjobs", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleCronJobYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "cronjobs", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetCronJob(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.recordAudit(r, "get", namespace, "cronjobs", item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "jobs", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListJobs(r.Context(), namespace)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r, "list", namespace, "jobs", "*")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleJobYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "jobs", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetJob(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.recordAudit(r, "get", namespace, "jobs", item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handleIngressYAML(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "ingresses", "get")
	if !ok {
		return
	}
	item, err := s.resources.GetIngress(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	item.ManagedFields = nil
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.recordAudit(r, "get", namespace, "ingresses", item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(data)})
}

func (s *Server) handlePodEvents(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	client, ok := s.kube.Client()
	if !ok || !s.kube.Ready() {
		writeError(w, http.StatusServiceUnavailable, "kubernetes client not ready")
		return
	}
	name := chi.URLParam(r, "name")
	events, err := client.CoreV1().Events(namespace).List(r.Context(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.kind=Pod,involvedObject.name=%s", name),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": events.Items})
}

func (s *Server) handleDeploymentEvents(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "deployments", "get")
	if !ok {
		return
	}
	client, ok := s.kube.Client()
	if !ok || !s.kube.Ready() {
		writeError(w, http.StatusServiceUnavailable, "kubernetes client not ready")
		return
	}
	name := chi.URLParam(r, "name")
	events, err := client.CoreV1().Events(namespace).List(r.Context(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.kind=Deployment,involvedObject.name=%s", name),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": events.Items})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"isAdmin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id, err := s.store.CreateUser(r.Context(), request.Username, hash)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.create", "-", "users", user.Username)
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		Username string `json:"username"`
		IsActive bool   `json:"isActive"`
		IsAdmin  bool   `json:"isAdmin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Guard: do not let the last active admin be demoted or deactivated — the
	// system would be unmanageable afterwards. "Last" is counted BEFORE this
	// update is applied; if the user is currently admin+active and is about
	// to lose either flag, require at least one other admin to survive.
	if user.IsAdmin && user.IsActive && (!request.IsAdmin || !request.IsActive) {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if count <= 1 {
			writeError(w, http.StatusConflict,
				"cannot demote or deactivate the last active administrator")
			return
		}
	}
	user.Username = request.Username
	user.IsActive = request.IsActive
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "users", user.Username)
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	caller, _ := s.userForRequest(r)
	if caller != nil && caller.ID == id {
		writeError(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Guard: deleting the last active admin would strand the system.
	if target.IsAdmin && target.IsActive {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if count <= 1 {
			writeError(w, http.StatusConflict,
				"cannot delete the last active administrator")
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.delete", "-", "users", target.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		GroupIDs []int `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update_groups", "-", "users", strconv.Itoa(id))
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ids, err := s.store.GetUserGroups(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"groupIds": ids})
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": groups})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, err := s.store.CreateGroup(r.Context(), request.Name)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	s.recordAudit(r, "admin.create", "-", "groups", request.Name)
	writeJSON(w, http.StatusCreated, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateGroup(r.Context(), id, request.Name); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "groups", request.Name)
	writeJSON(w, http.StatusOK, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.delete", "-", "groups", strconv.Itoa(id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		RoleIDs []int `json:"roleIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.SetGroupRoles(r.Context(), id, request.RoleIDs); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update_roles", "-", "groups", strconv.Itoa(id))
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ids, err := s.store.GetGroupRoles(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roleIds": ids})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": roles})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, err := s.store.CreateRole(r.Context(), request.Name, request.Description)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	s.recordAudit(r, "admin.create", "-", "roles", request.Name)
	writeJSON(w, http.StatusCreated, models.Role{ID: id, Name: request.Name, Description: request.Description})
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateRole(r.Context(), models.Role{ID: id, Name: request.Name, Description: request.Description}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "roles", request.Name)
	writeJSON(w, http.StatusOK, models.Role{ID: id, Name: request.Name, Description: request.Description})
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.delete", "-", "roles", strconv.Itoa(id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	permissions, err := s.store.ListNamespacePermissions(r.Context(), roleID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": permissions})
}

func (s *Server) handleAddRolePermission(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		ClusterID int    `json:"clusterId"` // 0 or omitted → "all clusters" wildcard
		Namespace string `json:"namespace"`
		Resource  string `json:"resource"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.AddNamespacePermission(r.Context(), roleID, request.ClusterID, request.Namespace, request.Resource, request.Action); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.add_permission", request.Namespace, "roles", strconv.Itoa(roleID))
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteNamespacePermission(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.delete_permission", "-", "permissions", strconv.Itoa(id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetLDAP(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	cfg.BindPassword = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleGetAzureAD(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	cfg.ClientSecret = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleUpdateLDAP(w http.ResponseWriter, r *http.Request) {
	var request models.LDAPConfig
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateLDAPConfig(r.Context(), request); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "ldap", "config")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleUpdateAzureAD(w http.ResponseWriter, r *http.Request) {
	var request models.AzureADConfig
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateAzureADConfig(r.Context(), request); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "azure_ad", "config")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleTestLDAP(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load ldap config")
		return
	}
	if err := auth.TestConnection(auth.LDAPConfig{
		Enabled:           cfg.Enabled,
		URL:               cfg.URL,
		Host:              cfg.Host,
		Port:              cfg.Port,
		UseSSL:            cfg.UseSSL,
		StartTLS:          cfg.StartTLS,
		SkipVerify:        cfg.SkipVerify,
		TimeoutSeconds:    cfg.TimeoutSeconds,
		BindDN:            cfg.BindDN,
		BindPassword:      cfg.BindPassword,
		UserBaseDN:        cfg.UserBaseDN,
		UserBaseDNs:       cfg.UserBaseDNs,
		UserFilter:        cfg.UserFilter,
		UsernameAttribute: cfg.UsernameAttribute,
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleTestAzureAD(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load azure ad config")
		return
	}
	if cfg.TenantID == "" || cfg.ClientID == "" {
		writeError(w, http.StatusBadRequest, "tenant and client id are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := auth.TestAzureConnection(ctx, auth.AzureADConfig{
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSearchLDAPUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	cfg, err := s.store.GetLDAPConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load ldap config")
		return
	}
	users, err := auth.SearchUsers(auth.LDAPConfig{
		Enabled:           cfg.Enabled,
		URL:               cfg.URL,
		Host:              cfg.Host,
		Port:              cfg.Port,
		UseSSL:            cfg.UseSSL,
		StartTLS:          cfg.StartTLS,
		SkipVerify:        cfg.SkipVerify,
		TimeoutSeconds:    cfg.TimeoutSeconds,
		BindDN:            cfg.BindDN,
		BindPassword:      cfg.BindPassword,
		UserBaseDN:        cfg.UserBaseDN,
		UserBaseDNs:       cfg.UserBaseDNs,
		UserFilter:        cfg.UserFilter,
		UsernameAttribute: cfg.UsernameAttribute,
	}, request.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": users})
}

func (s *Server) handleImportLDAPUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Usernames []string `json:"usernames"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	created := 0
	for _, username := range request.Usernames {
		if username == "" {
			continue
		}
		if _, err := s.store.GetUserByUsername(r.Context(), username); err == nil {
			continue
		}
		randomHash, err := auth.HashPassword(randomPassword())
		if err != nil {
			continue
		}
		if _, err := s.store.CreateUser(r.Context(), username, randomHash); err == nil {
			created++
		}
	}
	s.recordAudit(r, "admin.import", "-", "ldap_users", fmt.Sprintf("%d", created))
	writeJSON(w, http.StatusOK, map[string]interface{}{"created": created})
}

func randomPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "temporary-password"
	}
	return fmt.Sprintf("%x", b)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSession(w http.ResponseWriter, r *http.Request) {
	var request models.SessionSettings
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.SessionMinutes <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateSessionSettings(r.Context(), request); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "admin.update", "-", "session", "settings")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetCluster(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.GetKubeCredentials(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"method": creds.Method,
		"server": creds.Server,
		"active": creds.Active,
		"ready":  s.kube.Ready(),
		"lastError": s.kube.LastError(),
	})
}

func (s *Server) handleUpdateCluster(w http.ResponseWriter, r *http.Request) {
	logf("cluster update received")
	creds, err := parseClusterRequest(r)
	if err != nil {
		logf("cluster update invalid: %v", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	creds.Active = true
	if err := s.kube.ValidateCredentials(creds); err != nil {
		logf("cluster update validation failed: %v", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	logf("cluster update validation ok")
	if err := runWithTimeout(5*time.Second, func() error {
		return s.store.UpdateKubeCredentials(r.Context(), creds)
	}); err != nil {
		logf("cluster update store failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to store cluster credentials")
		return
	}
	logf("cluster update stored")
	if err := runWithTimeout(5*time.Second, func() error {
		return s.kube.ApplyCredentials(creds)
	}); err != nil {
		logf("cluster update apply failed: %v", err)
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}
	logf("cluster update applied")
	s.kube.StartAsync()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":    "starting",
		"active":    true,
		"ready":     s.kube.Ready(),
		"lastError": s.kube.LastError(),
	})
	logf("cluster update response sent")
	s.recordAudit(r, "admin.update", "-", "kube_cluster", creds.Method)
}

func runWithTimeout(timeout time.Duration, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("operation timed out")
	}
}

func (s *Server) handleValidateCluster(w http.ResponseWriter, r *http.Request) {
	creds, err := parseClusterRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.kube.ValidateCredentials(creds); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "valid"})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			offset = parsed
		}
	}
	userFilter := r.URL.Query().Get("user")
	actionFilter := r.URL.Query().Get("action")
	namespaceFilter := r.URL.Query().Get("namespace")
	startTime := parseTimeParam(r.URL.Query().Get("start"))
	endTime := parseTimeParam(r.URL.Query().Get("end"))
	logs, err := s.store.ListAuditLogs(r.Context(), limit, offset, userFilter, actionFilter, namespaceFilter, startTime, endTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	total, err := s.store.CountAuditLogs(r.Context(), userFilter, actionFilter, namespaceFilter, startTime, endTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	formatted := make([]map[string]interface{}, 0, len(logs))
	for _, entry := range logs {
		formatted = append(formatted, map[string]interface{}{
			"id": entry.ID,
			"timestamp": entry.Timestamp,
			"timestampFormatted": entry.Timestamp.In(s.timezone).Format("2006-01-02 15:04:05"),
			"user": entry.User,
			"action": entry.Action,
			"namespace": entry.Namespace,
			"resourceType": entry.ResourceType,
			"resourceName": entry.ResourceName,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": formatted,
		"total": total,
		"limit": limit,
		"offset": offset,
		"timezone": s.timezone.String(),
	})
}

func (s *Server) handleAuditLogsExport(w http.ResponseWriter, r *http.Request) {
	userFilter := r.URL.Query().Get("user")
	actionFilter := r.URL.Query().Get("action")
	namespaceFilter := r.URL.Query().Get("namespace")
	startTime := parseTimeParam(r.URL.Query().Get("start"))
	endTime := parseTimeParam(r.URL.Query().Get("end"))
	limit := 1000
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	logs, err := s.store.ListAuditLogs(r.Context(), limit, 0, userFilter, actionFilter, namespaceFilter, startTime, endTime)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-logs.csv")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"timestamp", "user", "action", "namespace", "resource_type", "resource_name"})
	for _, entry := range logs {
		_ = writer.Write([]string{
			entry.Timestamp.In(s.timezone).Format(time.RFC3339),
			entry.User,
			entry.Action,
			entry.Namespace,
			entry.ResourceType,
			entry.ResourceName,
		})
	}
	writer.Flush()
}

const (
	logoFileName     = "custom_logo"
	logoMetaFileName = "custom_logo.meta"
	maxLogoSize      = 5 << 20
)

func (s *Server) logoPath() string {
	return filepath.Join(s.dataDir, logoFileName)
}

func (s *Server) logoMetaPath() string {
	return filepath.Join(s.dataDir, logoMetaFileName)
}

func (s *Server) handleGetLogo(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.logoPath())
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	contentType := http.DetectContentType(data)
	if meta, err := os.ReadFile(s.logoMetaPath()); err == nil && len(meta) > 0 {
		contentType = strings.TrimSpace(string(meta))
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxLogoSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid upload")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxLogoSize+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}
	if len(data) == 0 || len(data) > maxLogoSize {
		writeError(w, http.StatusBadRequest, "invalid file size")
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	contentType := http.DetectContentType(data)
	if ext == ".svg" {
		contentType = "image/svg+xml"
	}
	if !strings.HasPrefix(contentType, "image/") {
		writeError(w, http.StatusBadRequest, "unsupported file type")
		return
	}

	if err := os.WriteFile(s.logoPath(), data, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store logo")
		return
	}
	_ = os.WriteFile(s.logoMetaPath(), []byte(contentType), 0o600)
	s.recordAudit(r, "admin.update", "-", "customization", "logo")
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteLogo(w http.ResponseWriter, r *http.Request) {
	_ = os.Remove(s.logoPath())
	_ = os.Remove(s.logoMetaPath())
	s.recordAudit(r, "admin.update", "-", "customization", "logo_removed")
	w.WriteHeader(http.StatusNoContent)
}

func parseTimeParam(value string) *time.Time {
	if value == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return &parsed
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return &parsed
	}
	return nil
}

func (s *Server) engineForRequest(r *http.Request) (*rbac.Engine, bool) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return nil, false
	}
	user, err := s.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil || !user.IsActive {
		return nil, false
	}
	if user.MustChangePassword {
		return nil, false
	}
	perms, err := s.store.ListPermissionsByUser(r.Context(), user.ID)
	if err != nil {
		return nil, false
	}
	return rbac.New(perms), true
}

func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, resource, action string) (string, bool) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	namespace := chi.URLParam(r, "namespace")
	if user.IsAdmin {
		return namespace, true
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	if !engine.Can(s.ActiveClusterID(), namespace, resource, action) {
		w.WriteHeader(http.StatusForbidden)
		return "", false
	}
	return namespace, true
}

func (s *Server) can(ctx context.Context, userID int, namespace, resource, action string) bool {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return false
	}
	if user.IsAdmin {
		return true
	}
	perms, err := s.store.ListPermissionsByUser(ctx, userID)
	if err != nil {
		return false
	}
	engine := rbac.New(perms)
	return engine.Can(s.ActiveClusterID(), namespace, resource, action)
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
		limiter = rate.NewLimiter(rate.Every(5*time.Second), 2)
		s.logLimiters[userID] = limiter
	}
	return limiter.Allow()
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func parseClusterRequest(r *http.Request) (models.KubeCredentials, error) {
	var request struct {
		Method           string `json:"method"`
		KubeconfigBase64 string `json:"kubeconfigBase64"`
		Token            string `json:"token"`
		Server           string `json:"server"`
		CACertBase64     string `json:"caCertBase64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return models.KubeCredentials{}, err
	}
	if request.Method == "" {
		return models.KubeCredentials{}, errors.New("method is required")
	}
	creds := models.KubeCredentials{Method: request.Method, Server: request.Server}
	if request.KubeconfigBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(request.KubeconfigBase64)
		if err != nil {
			return models.KubeCredentials{}, err
		}
		creds.Kubeconfig = data
	}
	if request.Token != "" {
		creds.Token = []byte(request.Token)
	}
	if request.CACertBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(request.CACertBase64)
		if err != nil {
			return models.KubeCredentials{}, err
		}
		creds.CACert = data
	}
	switch request.Method {
	case "kubeconfig":
		if len(creds.Kubeconfig) == 0 {
			return models.KubeCredentials{}, errors.New("kubeconfig is required")
		}
	case "token":
		if creds.Server == "" || len(creds.Token) == 0 {
			return models.KubeCredentials{}, errors.New("token method requires server and token")
		}
	default:
		return models.KubeCredentials{}, errors.New("unsupported method")
	}
	return creds, nil
}
