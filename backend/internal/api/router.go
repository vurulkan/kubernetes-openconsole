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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/recording"
	"k8s-dashboard/backend/internal/store"
	"k8s-dashboard/backend/internal/version"
)

type Server struct {
	store *store.Store
	audit *audit.Logger
	// clusters holds one connection per cluster; each request uses the
	// caller's selected cluster (see cluster_ctx.go).
	clusters     *kube.Registry
	resources    *kube.ResourceClient
	jwtKey       []byte
	logLimiters  map[int]*rate.Limiter
	logLimiterMu sync.Mutex
	staticDir    string
	dataDir      string
	timezone     *time.Location
	// Default cluster id — cached from the clusters.is_active row and
	// refreshed on activate/deactivate. Users who haven't picked a cluster
	// work on this one. 0 = no default.
	defaultClusterID atomic.Int64
	// sessionToucher batches last_used_at writes so AuthMiddleware doesn't
	// serialize every API call behind an UPDATE on SQLite's single writer.
	sessionToucher *store.SessionToucher
	// recorder captures pod exec sessions as asciicast files.
	recorder *recording.Manager
	// execSessions enforces MAX_EXEC_SESSIONS_PER_USER.
	execSessions execSessionTracker
	// prom caches each cluster's Prometheus client (cluster id → *prom.Client,
	// nil when none is configured); dropped when the cluster or its settings change.
	prom sync.Map
}

// sessionValidator is the AuthMiddleware adapter around *store.Store. Returning
// (false, nil) from Validate rejects a token; errors propagate so middleware
// can fail-open on a DB blip. Pre-tracking JWTs (no jti) never reach Validate
// — middleware shortcuts them in.
type sessionValidator struct {
	s *store.Store
	t *store.SessionToucher
}

func (v *sessionValidator) Validate(ctx context.Context, jti string) (bool, error) {
	status, err := v.s.LookupSession(ctx, jti)
	if err != nil {
		return false, err
	}
	// Row missing = JWT issued before session tracking existed. Honor it
	// until it expires naturally so the deployment doesn't log everyone out.
	if !status.Found {
		return true, nil
	}
	if status.Revoked || status.Expired {
		return false, nil
	}
	return true, nil
}

func (v *sessionValidator) Touch(jti string) { v.t.Touch(jti) }

// authValidator wires the Store + toucher into the shape AuthMiddleware wants.
// Returned fresh each time so AuthMiddleware never holds a reference it could
// outlive — in practice the Server lifetime is the process lifetime, so this
// is cosmetic.
func (s *Server) authValidator() auth.SessionValidator {
	return &sessionValidator{s: s.store, t: s.sessionToucher}
}

func NewServer(st *store.Store, auditLogger *audit.Logger, clusters *kube.Registry, recorder *recording.Manager, staticDir string, dataDir string, timeZone string) *Server {
	location, err := time.LoadLocation(timeZone)
	if err != nil {
		location = time.UTC
	}
	toucher := store.NewSessionToucher(st)
	s := &Server{
		store:          st,
		audit:          auditLogger,
		clusters:       clusters,
		resources:      kube.NewResourceClient(),
		jwtKey:         st.SigningKey(),
		logLimiters:    make(map[int]*rate.Limiter),
		staticDir:      staticDir,
		dataDir:        dataDir,
		timezone:       location,
		sessionToucher: toucher,
		recorder:       recorder,
	}
	clusterStatusFn = s.clusterStatus
	// Seed the default cluster id from whatever row is currently is_active.
	if cluster, err := st.GetActiveCluster(context.Background()); err == nil && cluster != nil {
		s.defaultClusterID.Store(int64(cluster.ID))
	}
	return s
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
	// Readiness: the DB handle is usable. Clusters are deliberately not part
	// of it: with several clusters (one per user's choice) a single
	// unreachable cluster must not take the whole console — including the
	// admin screens needed to fix it — out of service.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("db not reachable"))
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
		r.With(auth.AuthMiddleware(s.jwtKey, s.authValidator())).Get("/me", s.handleMe)
		r.With(auth.AuthMiddleware(s.jwtKey, s.authValidator())).Post("/change-password", s.handleChangePassword)
	})

	r.Get("/api/customization/logo", s.handleGetLogo)

	r.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddleware(s.jwtKey, s.authValidator()))
		r.Use(s.clusterMiddleware)
		r.Get("/api/cluster/active", s.handleGetActiveCluster)
		r.Post("/api/cluster/select", s.handleSelectCluster)
		r.Get("/api/features", s.handleFeatures)
		// Signed-in users only: the version isn't shown before login.
		r.Get("/api/version", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"version": version.Version})
		})
		r.Get("/api/views", s.handleListViews)
		r.Post("/api/views", s.handleSaveView)
		r.Put("/api/views/{id}", s.handleShareView)
		r.Delete("/api/views/{id}", s.handleDeleteView)
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
		r.Get("/api/namespaces/{namespace}/deployments/{name}/replicasets", s.handleDeploymentReplicaSets)
		r.Get("/api/namespaces/{namespace}/pods/{name}/restarts", s.handlePodRestarts)
		r.Get("/api/namespaces/{namespace}/metrics/pods", s.handlePodMetrics)
		r.Get("/api/namespaces/{namespace}/metrics/pods/{name}", s.handlePodMetricsHistory)
		for resource := range workloadKinds {
			r.Get("/api/namespaces/{namespace}/"+resource+"/{name}/restarts", s.handleWorkloadRestarts(resource))
			r.Get("/api/namespaces/{namespace}/metrics/"+resource+"/{name}", s.handleWorkloadMetricsHistory(resource))
			r.Get("/api/namespaces/{namespace}/"+resource+"/{name}/events", s.handleWorkloadEvents(resource))
		}
		r.Post("/api/namespaces/{namespace}/deployments/{name}/restart", s.handleDeploymentRestart)
		r.Post("/api/namespaces/{namespace}/deployments/{name}/scale", s.handleDeploymentScale)
		r.Get("/api/namespaces/{namespace}/daemonsets", s.handleDaemonSets)
		r.Get("/api/namespaces/{namespace}/daemonsets/{name}", s.handleDaemonSet)
		r.Get("/api/namespaces/{namespace}/daemonsets/{name}/yaml", s.handleDaemonSetYAML)
		r.Get("/api/namespaces/{namespace}/statefulsets", s.handleStatefulSets)
		r.Get("/api/namespaces/{namespace}/statefulsets/{name}", s.handleStatefulSet)
		r.Get("/api/namespaces/{namespace}/statefulsets/{name}/yaml", s.handleStatefulSetYAML)
		r.Post("/api/namespaces/{namespace}/statefulsets/{name}/scale", s.handleStatefulSetScale)
		r.Get("/api/namespaces/{namespace}/hpas", s.handleHPAs)
		r.Get("/api/namespaces/{namespace}/hpas/{name}", s.handleHPA)
		r.Get("/api/namespaces/{namespace}/hpas/{name}/yaml", s.handleHPAYAML)
		// Generic YAML apply (view-and-edit modal). One handler covers every
		// workload in resourceGVR; permission check is {resource}:edit.
		r.Post("/api/namespaces/{namespace}/{resource}/{name}/apply", s.handleYAMLApply)
		r.Get("/api/namespaces/{namespace}/services", s.handleServices)
		r.Get("/api/namespaces/{namespace}/services/{name}", s.handleService)
		r.Get("/api/namespaces/{namespace}/services/{name}/yaml", s.handleServiceYAML)
		r.Get("/api/namespaces/{namespace}/configmaps", s.handleConfigMaps)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}", s.handleConfigMap)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}/yaml", s.handleConfigMapYAML)
		r.Get("/api/namespaces/{namespace}/configmaps/{name}/data", s.handleConfigMapData)
		r.Get("/api/namespaces/{namespace}/secrets", s.handleSecrets)
		r.Get("/api/namespaces/{namespace}/secrets/{name}", s.handleSecret)
		r.Post("/api/namespaces/{namespace}/secrets/{name}/reveal", s.handleSecretReveal)
		r.Get("/api/namespaces/{namespace}/secrets/{name}/yaml", s.handleSecretYAML)
		r.Get("/api/namespaces/{namespace}/ingresses", s.handleIngresses)
		r.Get("/api/namespaces/{namespace}/ingresses/{name}/yaml", s.handleIngressYAML)
		r.Get("/api/namespaces/{namespace}/cronjobs", s.handleCronJobs)
		r.Get("/api/namespaces/{namespace}/cronjobs/{name}/yaml", s.handleCronJobYAML)
		r.Get("/api/namespaces/{namespace}/jobs", s.handleJobs)
		r.Get("/api/namespaces/{namespace}/jobs/{name}/yaml", s.handleJobYAML)
		r.Get("/ws/namespaces/{namespace}/pods/{name}/logs", s.handlePodLogsWS)
		r.Get("/ws/namespaces/{namespace}/pods/{name}/exec", s.handlePodExecWS)
		r.Get("/ws/namespaces/{namespace}/deployments/{name}/logs", s.handleDeploymentLogsWS)
		r.Get("/ws/namespaces/{namespace}/jobs/{name}/logs", s.handleJobLogsWS)
		// Live informer feed. ?namespace=<ns> filters; cluster-scoped events
		// (Namespace, Node, cluster-level K8s Events) always pass through.
		r.Get("/ws/events", s.handleEventsWS)

		// Recording writes check admin in the handler so denials are audited.
		r.Delete("/api/admin/recordings/{id}", s.handleDeleteRecording)
		r.Put("/api/admin/recordings/settings", s.handleUpdateRecordingSettings)
		r.Post("/api/admin/users/{id}/reset-password", s.handleResetUserPassword)
	})

	r.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddleware(s.jwtKey, s.authValidator()))
		r.Use(s.clusterMiddleware)
		r.Use(s.requireAdmin)
		r.Get("/api/admin/users", s.handleListUsers)
		r.Get("/api/admin/users/export", s.handleExportUsers)
		r.Get("/api/admin/groups/export", s.handleExportGroups)
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
		r.Get("/api/admin/clusters/{id}/prometheus", s.handleGetPrometheus)
		r.Put("/api/admin/clusters/{id}/prometheus", s.handlePutPrometheus)
		r.Post("/api/admin/clusters/{id}/prometheus/test", s.handleTestPrometheus)
		r.Get("/api/admin/clusters/{id}/prometheus/discover", s.handleDiscoverPrometheus)
		r.Put("/api/admin/cluster", s.handleUpdateCluster)
		r.Post("/api/admin/cluster/validate", s.handleValidateCluster)

		r.Get("/api/admin/audit-logs", s.handleAuditLogs)
		r.Get("/api/admin/audit-logs/export", s.handleAuditLogsExport)
		r.Get("/api/admin/audit-logs/facets", s.handleAuditFacets)

		// Session management (M4-B3 phase 1). List all/active, revoke a
		// single session row, or revoke every session for a user. Audit
		// entries carry session.revoke / session.revoke_all actions.
		r.Get("/api/admin/sessions", s.handleListSessions)
		r.Delete("/api/admin/sessions/{id}", s.handleRevokeSession)

		r.Get("/api/admin/recordings", s.handleListRecordings)
		r.Get("/api/admin/recordings/settings", s.handleGetRecordingSettings)
		r.Get("/api/admin/recordings/{id}", s.handleGetRecording)
		r.Get("/api/admin/recordings/{id}/cast", s.handleRecordingCast)
		r.Post("/api/admin/users/{id}/revoke-sessions", s.handleRevokeAllForUser)

		r.Post("/api/admin/customization/logo", s.handleUploadLogo)
		r.Delete("/api/admin/customization/logo", s.handleDeleteLogo)
	})

	if s.staticDir != "" {
		r.NotFound(s.serveSPA)
		r.MethodNotAllowed(s.serveSPA)
	}

	// Tracing: one server span per request, named after the chi route
	// pattern (set in requestLogger); probes and metrics are not traced.
	// With no OTLP endpoint configured the global provider is a no-op.
	return otelhttp.NewHandler(r, "http.request",
		otelhttp.WithFilter(func(r *http.Request) bool {
			switch r.URL.Path {
			case "/healthz", "/livez", "/readyz", "/metrics":
				return false
			}
			return true
		}),
	)
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
	bytes  int64
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
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

// quietPaths are logged at debug level when they succeed.
var quietPaths = map[string]bool{"/healthz": true, "/livez": true, "/readyz": true, "/metrics": true}

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
		} else if quietPaths[r.URL.Path] {
			// Kubelet probes and Prometheus scrapes arrive every few seconds;
			// successful ones are only logged at debug level.
			level = slog.LevelDebug
		}

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int64("duration_ms", duration.Milliseconds()),
			slog.String("remote_ip", clientIP(r)),
			slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
			slog.String("user_agent", r.UserAgent()),
		}
		if logpkg.ECS() {
			// ECS event.duration is in nanoseconds; milliseconds would turn
			// every fast request into 0.
			attrs[3] = slog.Int64("duration_ns", duration.Nanoseconds())
			attrs = append(attrs, slog.Int64("response_bytes", recorder.bytes))
		}
		// Name the request's span after the route pattern (low cardinality)
		// and link the log line to the trace.
		if span := trace.SpanFromContext(r.Context()); span.SpanContext().IsValid() {
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				span.SetName(r.Method + " " + rc.RoutePattern())
			}
			span.SetAttributes(attribute.String("openconsole.request_id", logpkg.RequestIDFrom(r.Context())))
			attrs = append(attrs, slog.String("trace_id", span.SpanContext().TraceID().String()))
		}
		slog.LogAttrs(r.Context(), level, "http.request", attrs...)
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
		s.recordLoginAudit(r, request.Username, audit.Locked, "too_many_failures", nil)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), request.Username)
	// No account yet: with LDAP auto-provisioning on, a directory user gets
	// one on their first sign-in. (A disabled account is found above and is
	// never re-created.)
	directoryChecked := false
	if errors.Is(err, sql.ErrNoRows) {
		if provisioned, ok := s.ldapAutoProvision(r, request.Username, request.Password); ok {
			user, err, directoryChecked = provisioned, nil, true
		}
	}
	if err != nil || !user.IsActive {
		LoginGate().recordFailure(gateKey)
		s.recordLoginAudit(r, request.Username, audit.Failed, "unknown_user", nil)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// The account's source decides how the password is checked. Directory
	// and Azure AD accounts never accept a local password, even if one was
	// stored before 2.13 (an old reset), so they can't bypass the directory.
	// Local accounts fall back to LDAP: users imported before 2.13 are still
	// tagged local until their first directory sign-in tags them.
	method := ""
	failReason := "bad_password"
	if directoryChecked {
		method = models.AuthSourceLDAP
	} else {
		switch user.AuthSource {
		case models.AuthSourceAzure:
			failReason = "azure_account"
		case models.AuthSourceLDAP:
			if s.ldapAuthenticate(r.Context(), request.Username, request.Password) {
				method = models.AuthSourceLDAP
			}
		default:
			if auth.ComparePassword(user.PasswordHash, request.Password) == nil {
				method = models.AuthSourceLocal
			} else if s.ldapAuthenticate(r.Context(), request.Username, request.Password) {
				method = models.AuthSourceLDAP
				_ = s.store.SetUserAuthSource(r.Context(), user.ID, models.AuthSourceLDAP)
			}
		}
	}

	if method == "" {
		LoginGate().recordFailure(gateKey)
		s.recordLoginAudit(r, request.Username, audit.Failed, failReason, audit.D{"account_source": user.AuthSource})
		// Same answer for every failure, so the response doesn't reveal
		// whether an account exists or where it signs in.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_ = s.store.MarkLogin(r.Context(), user.ID)
	s.recordLoginAudit(r, user.Username, audit.Success, "", audit.D{"login_method": method})
	LoginGate().recordSuccess(gateKey)
	s.issueTokenForUser(w, r, user)
}

// ldapAutoProvision handles a sign-in by someone who has no account yet.
// With "create accounts on first sign-in" enabled in the LDAP settings, the
// password is checked against the directory and, if it is right, an LDAP
// account is created under the name the directory uses, in the configured
// groups. If an LDAP account already exists under that name (the user typed
// "John" for "john") it is returned instead. ok is false when the setting is
// off or the directory refuses the credentials.
func (s *Server) ldapAutoProvision(r *http.Request, typed, password string) (*models.User, bool) {
	ctx := r.Context()
	cfg, err := s.store.GetLDAPConfig(ctx)
	if err != nil || !cfg.Enabled || !cfg.AutoProvision || strings.TrimSpace(typed) == "" {
		return nil, false
	}
	name, err := auth.LDAPAuthenticateUser(auth.LDAPConfig{
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
	}, typed, password)
	if err != nil {
		return nil, false
	}
	name = strings.TrimSpace(name)
	if existing, err := s.store.GetUserByUsername(ctx, name); err == nil {
		if existing.AuthSource == models.AuthSourceLDAP && existing.IsActive {
			return existing, true
		}
		return nil, false
	}
	hash, err := auth.HashPassword(randomPassword())
	if err != nil {
		return nil, false
	}
	id, err := s.store.CreateUser(ctx, name, hash)
	if err != nil {
		// Lost a race with a parallel first sign-in: use that account.
		if existing, getErr := s.store.GetUserByUsername(ctx, name); getErr == nil && existing.AuthSource == models.AuthSourceLDAP {
			return existing, true
		}
		return nil, false
	}
	_ = s.store.SetUserAuthSource(ctx, id, models.AuthSourceLDAP)
	groups := s.existingGroupIDs(ctx, cfg.AutoProvisionGroupIDs)
	if len(groups) > 0 {
		_ = s.store.SetUserGroups(ctx, id, groups)
	}
	user, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, false
	}
	s.auditEvent(r, models.AuditLog{
		User:         name,
		Verb:         audit.VerbCreate,
		ResourceType: audit.KindUser,
		ResourceName: name,
		AuthSource:   models.AuthSourceLDAP,
		Details:      audit.D{"account_source": models.AuthSourceLDAP, "groups": len(groups), "auto_provisioned": true},
	})
	return user, true
}

// existingGroupIDs drops ids of groups that no longer exist.
func (s *Server) existingGroupIDs(ctx context.Context, ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil
	}
	known := map[int]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	out := []int{}
	for _, id := range ids {
		if known[id] {
			out = append(out, id)
		}
	}
	return out
}

// ldapAuthenticate binds as the user against the configured directory; false
// when LDAP is off, unconfigured or the credentials are wrong.
func (s *Server) ldapAuthenticate(ctx context.Context, username, password string) bool {
	cfg, err := s.store.GetLDAPConfig(ctx)
	if err != nil || !cfg.Enabled {
		return false
	}
	return auth.LDAPAuthenticate(auth.LDAPConfig{
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
	}, username, password) == nil
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
	ttl := time.Duration(session.SessionMinutes) * time.Minute
	jti, err := newSessionID()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	token, err := auth.GenerateToken(s.jwtKey, user.ID, user.Username, jti, ttl)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	// Session row failure is logged but doesn't fail the login — the JWT is
	// still valid; the admin loses revocation visibility for this session
	// until the next login, which is the desired safety trade-off.
	if err := s.store.CreateSession(r.Context(), jti, user.ID, now, now.Add(ttl), clientIP(r), r.UserAgent()); err != nil {
		slog.Warn("could not record session", "user", user.Username, "error", err.Error())
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

// newSessionID returns a URL-safe 128-bit random string used as the JWT jti
// claim and the primary key in session_tokens. 128 bits of entropy is enough
// that we never need to worry about jti collisions.
func newSessionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
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
	identity, err := auth.AzureExchangeCode(ctx, auth.AzureADConfig{
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

	username := identity.Username
	linkedBy := ""
	user, err := s.store.GetUserByUsername(r.Context(), username)
	if errors.Is(err, sql.ErrNoRows) {
		// An admin may have pre-created the account under the person's
		// e-mail or UPN (or in another letter case). Only Azure AD accounts
		// nobody has signed in to yet can be claimed this way, so this can
		// never take over a local, LDAP or already used account.
		for _, candidate := range []struct{ name, via string }{
			{username, "username_case"}, {identity.Email, "email"}, {identity.UPN, "upn"},
		} {
			if candidate.name == "" {
				continue
			}
			if found, findErr := s.store.FindUnclaimedAzureAccount(r.Context(), candidate.name); findErr == nil {
				user, err, linkedBy = found, nil, candidate.via
				break
			}
		}
	}
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
	// Signed in through Azure AD: the stored password is random and must
	// never become resettable.
	if user.AuthSource != models.AuthSourceAzure {
		_ = s.store.SetUserAuthSource(r.Context(), user.ID, models.AuthSourceAzure)
	}
	_ = s.store.MarkLogin(r.Context(), user.ID)

	session, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load session settings")
		return
	}
	ttl := time.Duration(session.SessionMinutes) * time.Minute
	jti, err := newSessionID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate session id")
		return
	}
	token, err := auth.GenerateToken(s.jwtKey, user.ID, user.Username, jti, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	now := time.Now().UTC()
	if err := s.store.CreateSession(r.Context(), jti, user.ID, now, now.Add(ttl), clientIP(r), r.UserAgent()); err != nil {
		slog.Warn("could not record azure session", "user", user.Username, "error", err.Error())
	}
	login := audit.D{"login_method": models.AuthSourceAzure}
	if linkedBy != "" {
		login["linked_by"] = linkedBy
		login["signed_in_as"] = username
	}
	s.recordLoginAudit(r, user.Username, audit.Success, "", login)

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
		"namespaces":  engine.AllowedNamespaces(clusterIDFrom(r.Context())),
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
	if err := auth.CheckPasswordPolicy(request.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.NewPassword == request.CurrentPassword {
		writeError(w, http.StatusBadRequest, "the new password must differ from the current one")
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
	// Password change invalidates every session this user holds — including
	// the one that made this call. The browser then falls back to the login
	// screen on its next request, which is the intended UX.
	if err := s.store.RevokeAllForUser(r.Context(), user.ID); err != nil {
		slog.Warn("could not revoke sessions after password change", "user", user.Username, "error", err.Error())
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbChangePassword, ResourceType: audit.KindUser, ResourceName: user.Username})
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
		s.auditRead(r, audit.VerbList, "namespaces", "", "*")
		writeJSON(w, http.StatusOK, map[string]interface{}{"namespaces": all})
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	allowed := engine.AllowedNamespaces(clusterIDFrom(r.Context()))
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
	s.auditRead(r, audit.VerbList, "namespaces", "", "*")
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
			"resources": filterByFeatures(map[string][]string{
				"pods":         {"list", "get", "logs", "exec", "edit"},
				"deployments":  {"list", "get", "restart", "scale", "edit"},
				"daemonsets":   {"list", "get", "edit"},
				"statefulsets": {"list", "get", "scale", "edit"},
				"hpas":         {"list", "get", "edit"},
				"services":     {"list", "get", "edit"},
				"configmaps":   {"list", "get", "edit"},
				"secrets":      {"list", "get", "reveal", "edit"},
				"ingresses":    {"list", "get", "edit"},
				"cronjobs":     {"list", "get", "edit"},
				"jobs":         {"list", "get", "edit"},
			}),
		})
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	permissions := filterByFeatures(engine.AllowedResources(clusterIDFrom(r.Context()), namespace))
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
	s.auditRead(r, audit.VerbList, "pods", namespace, "*")
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
	s.auditRead(r, audit.VerbGet, "pods", namespace, pod.Name)
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
	s.auditRead(r, audit.VerbList, "deployments", namespace, "*")
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
	s.auditRead(r, audit.VerbGet, "deployments", namespace, item.Name)
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
	s.auditRead(r, audit.VerbList, "services", namespace, "*")
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
	s.auditRead(r, audit.VerbGet, "services", namespace, item.Name)
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
	s.auditRead(r, audit.VerbList, "configmaps", namespace, "*")
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
	s.auditRead(r, audit.VerbGet, "configmaps", namespace, item.Name)
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
	podName := chi.URLParam(r, "name")
	previous := r.URL.Query().Get("previous") == "true"
	container := r.URL.Query().Get("container")
	if container == "" {
		// Kubernetes refuses a log request without a container when the pod has several.
		if pod, err := s.resources.GetPod(r.Context(), namespace, podName); err == nil {
			container = defaultContainer(pod)
		}
	}
	podLogs := models.AuditLog{
		Verb:         audit.VerbLogs,
		ResourceType: "pod",
		Namespace:    namespace,
		ResourceName: podName,
		Details:      audit.D{"container": container},
	}
	if previous {
		podLogs.Details["previous"] = true
	}
	if !s.can(r.Context(), claims.UserID, namespace, "pods", "logs") {
		podLogs.Outcome, podLogs.Reason = audit.Denied, reasonForbidden
		s.auditEvent(r, podLogs)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.allowLogStream(claims.UserID) {
		podLogs.Outcome, podLogs.Reason = audit.RateLimited, reasonRateLimited
		s.auditEvent(r, podLogs)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	s.auditEvent(r, podLogs)

	client, ok := kubeFor(r).Client()
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
	MetricsLogStreamIncr()

	tail := int64(100)
	if value := r.URL.Query().Get("tail"); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > 0 {
			tail = parsed
		}
	}
	logOptions := &models.PodLogOptions{Container: container, TailLines: tail, Previous: previous}

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
	// The log ended (previous instance fully read, or the container stopped): say so, instead of a 1006 drop.
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// defaultContainer picks the container kubectl would: the one named by the
// kubectl.kubernetes.io/default-container annotation, else the first.
func defaultContainer(pod *corev1.Pod) string {
	if name := pod.Annotations["kubectl.kubernetes.io/default-container"]; name != "" {
		for _, c := range pod.Spec.Containers {
			if c.Name == name {
				return name
			}
		}
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name
	}
	return ""
}

// Typed client-go objects return with an empty TypeMeta (apiVersion/kind are
// omitempty on marshal), so without this the YAML the UI shows is missing the
// first two lines — which also makes a round-trip POST .../apply fail at the
// API server with "object has no kind". Set TypeMeta explicitly before every
// marshal.

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
	pod.TypeMeta = metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}
	data, err := yaml.Marshal(pod)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	item.TypeMeta = metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	item.TypeMeta = metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	item.TypeMeta = metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	s.auditRead(r, audit.VerbList, "ingresses", namespace, "*")
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
	s.auditRead(r, audit.VerbList, "cronjobs", namespace, "*")
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
	item.TypeMeta = metav1.TypeMeta{Kind: "CronJob", APIVersion: "batch/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.auditRead(r, audit.VerbGet, "cronjobs", namespace, item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	s.auditRead(r, audit.VerbList, "jobs", namespace, "*")
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
	item.TypeMeta = metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.auditRead(r, audit.VerbGet, "jobs", namespace, item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
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
	item.TypeMeta = metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"}
	data, err := yaml.Marshal(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.auditRead(r, audit.VerbGet, "ingresses", namespace, item.Name)
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(kube.PrettifyYAML(data))})
}

func (s *Server) handlePodEvents(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "pods", "get")
	if !ok {
		return
	}
	client, ok := kubeFor(r).Client()
	if !ok || !kubeFor(r).Ready() {
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

// handleWorkloadEvents lists a Deployment's, StatefulSet's or DaemonSet's own
// events (needs <kind>:get); its pods' events are on the pods.
func (s *Server) handleWorkloadEvents(resource string) http.HandlerFunc {
	kind := workloadKinds[resource]
	return func(w http.ResponseWriter, r *http.Request) {
		namespace, ok := s.requirePermission(w, r, resource, "get")
		if !ok {
			return
		}
		client, ok := kubeFor(r).Client()
		if !ok || !kubeFor(r).Ready() {
			writeError(w, http.StatusServiceUnavailable, "kubernetes client not ready")
			return
		}
		name := chi.URLParam(r, "name")
		events, err := client.CoreV1().Events(namespace).List(r.Context(), metav1.ListOptions{
			FieldSelector: fmt.Sprintf("involvedObject.kind=%s,involvedObject.name=%s", kind, name),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch events")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": events.Items})
	}
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
		// Source "azure" pre-creates an Azure AD account (no password; the
		// first Microsoft sign-in uses it). Empty or "local" is a local user.
		Source   string `json:"source"`
		GroupIDs []int  `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	source := strings.ToLower(strings.TrimSpace(request.Source))
	if source == "" {
		source = models.AuthSourceLocal
	}
	var password string
	switch source {
	case models.AuthSourceLocal:
		if err := auth.CheckPasswordPolicy(request.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		password = request.Password
	case models.AuthSourceAzure:
		// Never usable: Azure AD accounts don't sign in with a password.
		password = randomPassword()
	default:
		writeError(w, http.StatusBadRequest, "source must be local or azure (LDAP users are imported)")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id, err := s.store.CreateUser(r.Context(), request.Username, hash)
	if err != nil {
		writeError(w, http.StatusConflict, "a user with this name already exists")
		return
	}
	if source != models.AuthSourceLocal {
		_ = s.store.SetUserAuthSource(r.Context(), id, source)
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
	if len(request.GroupIDs) > 0 {
		if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
			writeError(w, http.StatusBadRequest, "user created, but the groups could not be set: "+err.Error())
			return
		}
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindUser, ResourceName: user.Username,
		Details: audit.D{"account_source": source, "is_admin": user.IsAdmin, "groups": len(request.GroupIDs)}})
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
	before := *user
	user.Username = request.Username
	user.IsActive = request.IsActive
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	changed := []string{}
	if before.Username != user.Username {
		changed = append(changed, "username")
	}
	if before.IsActive != user.IsActive {
		changed = append(changed, "is_active")
	}
	if before.IsAdmin != user.IsAdmin {
		changed = append(changed, "is_admin")
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindUser, ResourceName: user.Username,
		Details: audit.D{"changed": changed, "is_admin": user.IsAdmin, "is_active": user.IsActive}})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindUser, ResourceName: target.Username,
		Details: audit.D{"account_source": target.AuthSource, "is_admin": target.IsAdmin}})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindUser, ResourceName: s.userNameByID(r, id),
		Details: audit.D{"changed": []string{"groups"}, "groups": len(request.GroupIDs)}})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindGroup, ResourceName: request.Name})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindGroup, ResourceName: request.Name, Details: audit.D{"changed": []string{"name"}}})
	writeJSON(w, http.StatusOK, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	name := s.groupNameByID(r, id)
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindGroup, ResourceName: name, Details: audit.D{"id": id}})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindGroup, ResourceName: s.groupNameByID(r, id),
		Details: audit.D{"changed": []string{"roles"}, "count": len(request.RoleIDs)}})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindRole, ResourceName: request.Name})
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
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindRole, ResourceName: request.Name})
	writeJSON(w, http.StatusOK, models.Role{ID: id, Name: request.Name, Description: request.Description})
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	name := s.roleNameByID(r, id)
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindRole, ResourceName: name, Details: audit.D{"id": id}})
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
	clusterName := ""
	if request.ClusterID > 0 {
		clusterName, _ = s.store.GetClusterName(r.Context(), request.ClusterID)
	}
	s.recordPermissionAudit(r, audit.VerbCreate, models.NamespacePermission{
		RoleID: roleID, ClusterID: request.ClusterID, ClusterName: clusterName,
		Namespace: request.Namespace, Resource: request.Resource, Action: request.Action,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	perm, err := s.store.GetNamespacePermission(r.Context(), id)
	if err != nil {
		perm = &models.NamespacePermission{ID: id}
	}
	if err := s.store.DeleteNamespacePermission(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordPermissionAudit(r, audit.VerbDelete, *perm)
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
	s.recordSettingsUpdate(r, "ldap", nil)
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
	s.recordSettingsUpdate(r, "azure_ad", nil)
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
	type result struct {
		auth.LDAPUser
		// Exists: an OpenConsole account with this name is already there.
		Exists bool `json:"exists"`
	}
	items := make([]result, 0, len(users))
	for _, u := range users {
		_, err := s.store.GetUserByUsername(r.Context(), u.Username)
		items = append(items, result{LDAPUser: u, Exists: err == nil})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleImportLDAPUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Usernames []string `json:"usernames"`
		// Optional groups every newly imported user is added to, so they
		// can see something on their first sign-in.
		GroupIDs []int `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var created, skipped []string
	for _, username := range request.Usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		if _, err := s.store.GetUserByUsername(r.Context(), username); err == nil {
			skipped = append(skipped, username)
			continue
		}
		randomHash, err := auth.HashPassword(randomPassword())
		if err != nil {
			continue
		}
		id, err := s.store.CreateUser(r.Context(), username, randomHash)
		if err != nil {
			continue
		}
		_ = s.store.SetUserAuthSource(r.Context(), id, models.AuthSourceLDAP)
		if len(request.GroupIDs) > 0 {
			_ = s.store.SetUserGroups(r.Context(), id, request.GroupIDs)
		}
		created = append(created, username)
	}
	summary := strings.Join(created, ", ")
	if r := []rune(summary); len(r) > 500 {
		summary = string(r[:500]) + "…"
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbImport, ResourceType: audit.KindUser, ResourceName: "*",
		Details: audit.D{"account_source": models.AuthSourceLDAP, "count": len(created), "groups": len(request.GroupIDs), "summary": summary}})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"created":         len(created),
		"createdUsers":    created,
		"skippedExisting": skipped,
	})
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
	s.recordSettingsUpdate(r, "session", audit.D{"summary": "session_minutes=" + strconv.Itoa(request.SessionMinutes)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleGetCluster is the pre-multi-cluster status endpoint, kept for API
// compatibility: it now describes the default cluster.
func (s *Server) handleGetCluster(w http.ResponseWriter, r *http.Request) {
	id := s.DefaultClusterID()
	if id == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"method": "", "server": "", "active": false, "ready": false, "lastError": ""})
		return
	}
	c, err := s.store.GetCluster(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	lastError := ""
	ready := false
	if m, err := s.clusters.Get(r.Context(), id); err != nil {
		lastError = err.Error()
	} else {
		ready = m.Ready()
		lastError = m.LastError()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"method":    c.Method,
		"server":    c.Server,
		"active":    true,
		"ready":     ready,
		"lastError": lastError,
	})
}

// handleUpdateCluster was the single-cluster write endpoint. Clusters are
// managed through /api/admin/clusters now.
func (s *Server) handleUpdateCluster(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, "single-cluster settings were replaced by Admin → Clusters (/api/admin/clusters)")
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
	if err := kube.ValidateCredentials(creds); err != nil {
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
	filter, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	logs, err := s.store.ListAuditLogsFiltered(r.Context(), limit, offset, filter)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	total, err := s.store.CountAuditLogsFiltered(r.Context(), filter)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	type auditItem struct {
		models.AuditLog
		TimestampFormatted string `json:"timestampFormatted"`
	}
	formatted := make([]auditItem, 0, len(logs))
	for _, entry := range logs {
		formatted = append(formatted, auditItem{entry, entry.Timestamp.In(s.timezone).Format("2006-01-02 15:04:05")})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":    formatted,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"timezone": s.timezone.String(),
	})
}

// auditFilterFrom reads the audit filter query parameters: user, action
// (contains; "family.*" for a whole family; a trailing outcome as in
// deployment.restart.success is split off), actionExact=1, verb, outcome,
// resourceType, resourceName, cluster, namespace, start, end.
func auditFilterFrom(w http.ResponseWriter, r *http.Request) (store.AuditFilter, bool) {
	q := r.URL.Query()
	f := store.AuditFilter{
		User:         q.Get("user"),
		Action:       q.Get("action"),
		ActionExact:  q.Get("actionExact") == "1" || q.Get("actionExact") == "true",
		Verb:         q.Get("verb"),
		Outcome:      q.Get("outcome"),
		ResourceType: q.Get("resourceType"),
		ResourceName: q.Get("resourceName"),
		Cluster:      q.Get("cluster"),
		Namespace:    q.Get("namespace"),
		Start:        parseTimeParam(q.Get("start")),
		End:          parseTimeParam(q.Get("end")),
	}
	if f.Outcome != "" && !slices.Contains(audit.Outcomes, f.Outcome) {
		writeError(w, http.StatusBadRequest, "outcome must be one of "+strings.Join(audit.Outcomes, ", "))
		return f, false
	}
	if f.Verb != "" && !slices.Contains(audit.Verbs, f.Verb) {
		writeError(w, http.StatusBadRequest, "unknown verb")
		return f, false
	}
	return f, true
}

// handleAuditFacets lists the actions, users and namespaces found in the
// audit log, for the filter suggestions in Admin → Audit Logs.
func (s *Server) handleAuditFacets(w http.ResponseWriter, r *http.Request) {
	facets, err := s.store.AuditFacets(r.Context(), 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read audit facets")
		return
	}
	writeJSON(w, http.StatusOK, facets)
}

func (s *Server) handleAuditLogsExport(w http.ResponseWriter, r *http.Request) {
	filter, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	limit := 1000
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	logs, err := s.store.ListAuditLogsFiltered(r.Context(), limit, 0, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-logs.csv")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"timestamp", "user", "action", "verb", "outcome", "reason", "cluster", "namespace",
		"resource_type", "resource_name", "details", "source_ip", "user_agent", "auth_source", "request_id"})
	for _, entry := range logs {
		details := ""
		if len(entry.Details) > 0 {
			b, _ := json.Marshal(entry.Details)
			details = string(b)
		}
		_ = writer.Write([]string{
			entry.Timestamp.In(s.timezone).Format(time.RFC3339),
			entry.User,
			entry.Action,
			entry.Verb,
			entry.Outcome,
			entry.Reason,
			entry.Cluster,
			entry.Namespace,
			entry.ResourceType,
			entry.ResourceName,
			details,
			entry.SourceIP,
			entry.UserAgent,
			entry.AuthSource,
			entry.RequestID,
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
	s.recordSettingsUpdate(r, "logo", audit.D{"size_bytes": len(data)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteLogo(w http.ResponseWriter, r *http.Request) {
	_ = os.Remove(s.logoPath())
	_ = os.Remove(s.logoMetaPath())
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindSettings, ResourceName: "logo"})
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
	if !featureAllows(resource, action) {
		s.auditReadDenied(r, resource, action, reasonFeatureDisabled)
		writeError(w, http.StatusForbidden, "this feature is disabled by the operator")
		return "", false
	}
	if user.IsAdmin {
		return namespace, true
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	if !engine.Can(clusterIDFrom(r.Context()), namespace, resource, action) {
		s.auditReadDenied(r, resource, action, reasonForbidden)
		w.WriteHeader(http.StatusForbidden)
		return "", false
	}
	return namespace, true
}

func (s *Server) can(ctx context.Context, userID int, namespace, resource, action string) bool {
	if !featureAllows(resource, action) {
		return false
	}
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
	return engine.Can(clusterIDFrom(ctx), namespace, resource, action)
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
