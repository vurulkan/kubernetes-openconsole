package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/time/rate"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/problem"
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
	// execSessions enforces MAX_EXEC_SESSIONS_PER_USER; execIdleTimeout closes
	// a shell after this long without stdin (SetExecLimits).
	execSessions    execSessionTracker
	execIdleTimeout time.Duration
	// disabledFeatures: the FEATURE_* flags that are off (SetDisabledFeatures).
	disabledFeatures map[string]bool
	// passwordMinLength: PASSWORD_MIN_LENGTH (SetPasswordMinLength).
	passwordMinLength int
	// azureAuthority: the Entra ID sign-in host (SetAzureAuthority).
	azureAuthority string
	// graphURL overrides the Microsoft Graph host (tests); empty = from azureAuthority.
	graphURL string
	// deployLimiters: per-user token buckets for write actions (allowDeployAction).
	deployLimitersMu sync.Mutex
	deployLimiters   map[int]*rate.Limiter
	// prom caches each cluster's Prometheus client (cluster id → *prom.Client,
	// nil when none is configured); dropped when the cluster or its settings change.
	prom sync.Map
	// overview caches the admin overview per cluster id (overviewEntry, 15 s).
	overview sync.Map
	// overviewHistory caches the overview's Prometheus history per cluster (historyEntry, 5 min).
	overviewHistory sync.Map
	// overviewHistoryBusy marks a cluster whose history is being refreshed in the background.
	overviewHistoryBusy sync.Map
	// nodes caches the node list per cluster id (nodesEntry, 15 s).
	nodes sync.Map
	// nodeHistory caches a node's Prometheus history (nodeHistoryKey → historyEntry, one step).
	nodeHistory sync.Map
	// keyLimits rate-limits API keys and thins out their last-use writes.
	keyLimits apiKeyLimits
	// facets caches the audit filter suggestions (facetsEntry, 60 s): seven
	// DISTINCT scans of the whole audit log on every Audit Logs visit.
	facets atomic.Pointer[facetsEntry]
	// ws tracks open WebSocket handlers so shutdown can wait for them;
	// stopping is set when shutdown begins.
	ws       sync.WaitGroup
	stopping atomic.Bool
	// backups: Admin → Backups (backups.go).
	backups        *backup.Manager
	backupInterval time.Duration
	backupDownload bool
	keyExternal    bool
}

// SetPasswordMinLength sets PASSWORD_MIN_LENGTH. Call it before serving.
func (s *Server) SetPasswordMinLength(n int) {
	if n > 0 {
		s.passwordMinLength = n
	}
}

// SetAzureAuthority sets the Entra ID sign-in host (AZURE_AD_AUTHORITY) for
// sign-in and Prometheus tokens. Call it before serving.
func (s *Server) SetAzureAuthority(v string) {
	if v != "" {
		s.azureAuthority = strings.TrimRight(v, "/")
	}
}

// BeginShutdown marks the server as stopping, before the base context of
// the HTTP server is cancelled (which ends every WebSocket).
func (s *Server) BeginShutdown() { s.stopping.Store(true) }

// Drain waits for the WebSocket handlers to finish (each writes its end
// audit and closes its recording) and then for pending audit writes, or
// until ctx ends.
func (s *Server) Drain(ctx context.Context) {
	done := make(chan struct{})
	go func() { s.ws.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("shutdown: WebSocket sessions still open")
	}
	s.audit.Wait(ctx)
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

		execSessions:      execSessionTracker{limit: defaultMaxExecSessionsPerUser},
		execIdleTimeout:   defaultExecIdleTimeout,
		disabledFeatures:  map[string]bool{},
		passwordMinLength: auth.DefaultMinPasswordLength,
		azureAuthority:    auth.DefaultAzureAuthority,
		deployLimiters:    map[int]*rate.Limiter{},
	}
	clusterStatusFn = s.clusterStatus
	// Seed the default cluster id from whatever row is currently is_active.
	if cluster, err := st.GetActiveCluster(context.Background()); err == nil && cluster != nil {
		s.defaultClusterID.Store(int64(cluster.ID))
	}
	return s
}

func (s *Server) Router() http.Handler {
	r := s.routes()
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

// routes is every route; openapi_test.go walks it against openapi.yaml.
func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(corsMiddleware)
	r.Use(securityHeaders)
	r.Use(requestIDMiddleware)
	r.Use(recoverMiddleware)
	r.Use(requestLogger)
	r.Use(limitBody)

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
		r.With(s.authn()).Get("/me", s.handleMe)
		r.With(s.authn()).Post("/change-password", s.handleChangePassword)
		r.Post("/2fa/verify", s.handleTwoFactorVerify)
	})

	r.Get("/api/customization/logo", s.handleGetLogo)
	// The API description; no sign-in, nothing secret in it.
	r.Get("/api/openapi.json", handleOpenAPI)

	r.Group(func(r chi.Router) {
		r.Use(s.authn())
		r.Use(s.clusterMiddleware)
		r.Get("/api/cluster/active", s.handleGetActiveCluster)
		r.Post("/api/cluster/select", s.handleSelectCluster)
		r.Get("/api/features", s.handleFeatures)
		r.Post("/api/ws-ticket", s.handleWSTicket)
		// Admin only; checked in the handler so a refusal is audited.
		r.Get("/api/admin/overview", s.handleOverview)
		r.Get("/api/admin/overview/history", s.handleOverviewHistory)
		r.Get("/api/admin/nodes", s.handleNodes)
		r.Get("/api/admin/nodes/{name}", s.handleNode)
		r.Get("/api/admin/nodes/{name}/metrics/history", s.handleNodeHistory)
		// Signed-in users only: the version isn't shown before login.
		// API keys: web session only (checked in the handlers so a refusal is audited).
		r.Get("/api/me/api-keys", s.handleListAPIKeys)
		// Two-factor sign-in: web session only (denyAPIKey in the handlers).
		r.Post("/api/me/2fa/setup", s.handleTwoFactorSetup)
		r.Post("/api/me/2fa/confirm", s.handleTwoFactorConfirm)
		r.Post("/api/me/2fa/recovery-codes", s.handleTwoFactorRecoveryCodes)
		r.Delete("/api/me/2fa", s.handleTwoFactorDisable)
		r.Get("/api/me/api-keys/ceiling", s.handleAPIKeyCeiling)
		r.Post("/api/me/api-keys", s.handleCreateAPIKey)
		r.Put("/api/me/api-keys/{id}", s.handleUpdateAPIKey)
		r.Post("/api/me/api-keys/{id}/regenerate", s.handleRegenerateAPIKey)
		r.Post("/api/me/api-keys/{id}/revoke", s.handleRevokeAPIKey)
		r.Delete("/api/me/api-keys/{id}", s.handleDeleteAPIKey)
		r.Get("/api/version", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"version": version.Version})
		})
		r.Get("/api/views", s.handleListViews)
		r.Post("/api/views", s.handleSaveView)
		r.Put("/api/views/{id}", s.handleShareView)
		r.Delete("/api/views/{id}", s.handleDeleteView)
		r.Get("/api/clusters/public", s.handleListClustersPublic)
		r.Get("/api/search", s.handleSearch)
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
		r.Get("/api/namespaces/{namespace}/pods/{name}/logs", s.handlePodLogs)
		r.Post("/api/namespaces/{namespace}/pods/{name}/exec", s.handlePodExecCommand)
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

	// Admin writes: adminWrite checks admin itself so that a refusal is
	// audited too (every answer is).
	r.Group(func(r chi.Router) {
		r.Use(s.authn())
		r.Use(s.clusterMiddleware)
		r.Post("/api/admin/users", s.adminWrite(audit.VerbCreate, audit.KindUser, s.handleCreateUser))
		r.Put("/api/admin/users/{id}", s.adminWrite(audit.VerbUpdate, audit.KindUser, s.handleUpdateUser))
		r.Delete("/api/admin/users/{id}", s.adminWrite(audit.VerbDelete, audit.KindUser, s.handleDeleteUser))
		r.Put("/api/admin/users/{id}/groups", s.adminWrite(audit.VerbUpdate, audit.KindUser, s.handleSetUserGroups))
		r.Post("/api/admin/users/{id}/reset-2fa", s.adminWrite(audit.VerbReset, audit.KindTwoFactor, s.handleResetUserTwoFactor))
		r.Post("/api/admin/groups", s.adminWrite(audit.VerbCreate, audit.KindGroup, s.handleCreateGroup))
		r.Put("/api/admin/groups/{id}", s.adminWrite(audit.VerbUpdate, audit.KindGroup, s.handleUpdateGroup))
		r.Delete("/api/admin/groups/{id}", s.adminWrite(audit.VerbDelete, audit.KindGroup, s.handleDeleteGroup))
		r.Put("/api/admin/groups/{id}/roles", s.adminWrite(audit.VerbUpdate, audit.KindGroup, s.handleSetGroupRoles))
		r.Post("/api/admin/roles", s.adminWrite(audit.VerbCreate, audit.KindRole, s.handleCreateRole))
		r.Put("/api/admin/roles/{id}", s.adminWrite(audit.VerbUpdate, audit.KindRole, s.handleUpdateRole))
		r.Delete("/api/admin/roles/{id}", s.adminWrite(audit.VerbDelete, audit.KindRole, s.handleDeleteRole))
		r.Post("/api/admin/roles/{id}/permissions", s.adminWrite(audit.VerbCreate, audit.KindPermission, s.handleAddRolePermission))
		r.Delete("/api/admin/permissions/{id}", s.adminWrite(audit.VerbDelete, audit.KindPermission, s.handleDeletePermission))
		r.Put("/api/admin/ldap", s.adminWrite(audit.VerbUpdate, audit.KindSettings, s.handleUpdateLDAP))
		r.Put("/api/admin/azure-ad", s.adminWrite(audit.VerbUpdate, audit.KindSettings, s.handleUpdateAzureAD))
		r.Put("/api/admin/session", s.adminWrite(audit.VerbUpdate, audit.KindSettings, s.handleUpdateSession))
		r.Post("/api/admin/azure-ad/users/import", s.adminWrite(audit.VerbImport, audit.KindUser, s.handleImportAzureUsers))
		r.Put("/api/admin/clusters/order", s.adminWrite(audit.VerbUpdate, audit.KindCluster, s.handlePutClusterOrder))
		r.Post("/api/admin/customization/logo", s.adminWrite(audit.VerbUpdate, audit.KindSettings, s.handleUploadLogo))
		r.Delete("/api/admin/customization/logo", s.adminWrite(audit.VerbDelete, audit.KindSettings, s.handleDeleteLogo))
	})

	r.Group(func(r chi.Router) {
		r.Use(s.authn())
		r.Use(s.clusterMiddleware)
		r.Use(s.requireAdmin)
		r.Get("/api/admin/users", s.handleListUsers)
		r.Get("/api/admin/users/export", s.handleExportUsers)
		r.Get("/api/admin/groups/export", s.handleExportGroups)
		// API keys of every user (M15): web session only, see apikeys_admin.go.
		r.Get("/api/admin/api-keys", s.handleAdminListAPIKeys)
		r.Get("/api/admin/api-keys/export", s.handleExportAPIKeys)
		r.Post("/api/admin/api-keys/{id}/revoke", s.handleAdminRevokeAPIKey)
		r.Post("/api/admin/users/{id}/revoke-api-keys", s.handleRevokeUserAPIKeys)
		r.Get("/api/admin/users/{id}/api-access", s.handleUserAPIAccess)
		r.Get("/api/admin/users/{id}/groups", s.handleGetUserGroups)

		r.Get("/api/admin/groups", s.handleListGroups)
		r.Get("/api/admin/groups/{id}/roles", s.handleGetGroupRoles)

		r.Get("/api/admin/roles", s.handleListRoles)
		r.Get("/api/admin/roles/{id}/permissions", s.handleListRolePermissions)

		r.Get("/api/admin/ldap", s.handleGetLDAP)
		r.Post("/api/admin/ldap/test", s.handleTestLDAP)
		r.Post("/api/admin/ldap/users/search", s.handleSearchLDAPUsers)
		r.Post("/api/admin/ldap/users/import", s.handleImportLDAPUsers)
		r.Get("/api/admin/azure-ad", s.handleGetAzureAD)
		r.Post("/api/admin/azure-ad/test", s.handleTestAzureAD)
		r.Post("/api/admin/azure-ad/graph/test", s.handleTestAzureGraph)
		r.Post("/api/admin/azure-ad/users/search", s.handleSearchAzureUsers)

		r.Get("/api/admin/backups", s.handleListBackups)
		r.Post("/api/admin/backups", s.handleCreateBackup)
		r.Get("/api/admin/backups/{name}", s.handleDownloadBackup)

		r.Get("/api/admin/session", s.handleGetSession)

		// Multi-cluster CRUD (admin only).
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

	})

	// An unknown /api or /ws path answers JSON (an agent would otherwise get
	// the SPA's index.html with 200); everything else is the SPA.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if isAPIPath(req.URL.Path) || s.staticDir == "" {
			writeError(w, http.StatusNotFound, problem.NotFound)
			return
		}
		s.serveSPA(w, req)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		if isAPIPath(req.URL.Path) || s.staticDir == "" {
			for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				if r.Match(chi.NewRouteContext(), m, req.URL.Path) {
					w.Header().Add("Allow", m)
				}
			}
			writeError(w, http.StatusMethodNotAllowed, problem.MethodNotAllowed)
			return
		}
		s.serveSPA(w, req)
	})

	return r
}

func isAPIPath(p string) bool {
	return p == "/api" || p == "/ws" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/ws/")
}
