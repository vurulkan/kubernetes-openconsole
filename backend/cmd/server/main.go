package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s-dashboard/backend/internal/api"
	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/config"
	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/recording"
	"k8s-dashboard/backend/internal/store"
	"k8s-dashboard/backend/internal/telemetry"
	"k8s-dashboard/backend/internal/version"
)

func main() {
	cfg := config.Load()
	// APP_VERSION overrides the built-in version (e.g. a canary label).
	if cfg.Version == "" {
		cfg.Version = version.Version
	}
	logger := logpkg.New(logpkg.Config{
		Level:        cfg.LogLevel,
		Format:       cfg.LogFormat,
		Output:       cfg.LogOutput,
		AddSource:    cfg.LogAddSource,
		Service:      "openconsole",
		Version:      cfg.Version,
		Env:          cfg.Env,
		IncludeAudit: cfg.LogIncludeAudit,
	})
	logpkg.SetDefault(logger)
	// After the logger: its "tracing enabled" line is in LOG_FORMAT too.
	shutdownTracing, err := telemetry.Setup(context.Background(), cfg.Version, cfg.Env)
	if err != nil {
		slog.Warn("tracing disabled: exporter setup failed", slog.Any("error", err))
	}

	slog.Info("starting openconsole",
		slog.String("port", cfg.Port),
		slog.String("data_path", cfg.DataPath),
		slog.String("timezone", cfg.TimeZone),
		slog.String("log_format", cfg.LogFormat),
		slog.String("log_level", cfg.LogLevel),
	)

	if err := api.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		fatal("config error", err)
	}
	if err := api.SetOrigins(cfg.AllowedOrigins, cfg.WSOriginCheck); err != nil {
		fatal("config error", err)
	}

	currentKey, err := config.ReadKey(cfg.EncryptionKeyFile, cfg.EncryptionKey)
	if err != nil {
		fatal("ENCRYPTION_KEY", err)
	}
	previousKey, err := config.ReadKey(cfg.EncryptionKeyPreviousFile, cfg.EncryptionKeyPrevious)
	if err != nil {
		fatal("ENCRYPTION_KEY_PREVIOUS", err)
	}

	backupDir := cfg.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(filepath.Dir(cfg.DataPath), "backups")
	}
	database, err := db.OpenWithBackup(cfg.DataPath, backupDir)
	if err != nil {
		fatal("db error", err)
	}

	stor, err := store.NewWithKeys(database.Conn, store.Keys{Current: currentKey, Previous: previousKey, Lost: cfg.EncryptionKeyLost})
	if err != nil {
		fatal("store error", err)
	}
	stor.SetReadConn(database.Read)

	defaultHash, err := auth.HashPassword("admin")
	if err != nil {
		fatal("hash error", err)
	}
	if err := stor.EnsureDefaultAdmin(context.Background(), defaultHash); err != nil {
		fatal("admin seed error", err)
	}

	// One connection per cluster, opened on first use; each user works on
	// the cluster they selected (see api/cluster_ctx.go).
	clusters := kube.NewRegistry(func(ctx context.Context, id int) (models.KubeCredentials, error) {
		c, err := stor.GetCluster(ctx, id)
		if err != nil {
			return models.KubeCredentials{}, err
		}
		return c.Credentials, nil
	})
	startRestartHistory(stor, clusters, cfg.RestartHistoryDays)
	warmClusters(context.Background(), stor, clusters)

	auditLogger := audit.New(stor)
	auditLogger.SetConsoleMirror(cfg.LogIncludeAudit)
	auditLogger.SetMetricHook(api.MetricsAuditIncr)
	auditLogger.SetFailureHook(api.MetricsAuditFailed)
	if err := auditLogger.UpgradeLegacy(context.Background()); err != nil {
		slog.Warn("audit upgrade failed; older rows keep the pre-2.17 format", slog.Any("error", err))
	}
	if cfg.TwoFactorResetUser != "" {
		resetTwoFactor(stor, auditLogger, cfg.TwoFactorResetUser)
	}
	auditLogger.StartRetention(context.Background(), cfg.LogRetentionDays, cfg.APIKeyReadRetentionDays, cfg.AuditPurgeInterval)

	recDir := cfg.Recording.Dir
	if recDir == "" {
		recDir = filepath.Join(filepath.Dir(cfg.DataPath), "recordings")
	}
	recorder, err := recording.New(context.Background(), stor, auditLogger, recDir, models.RecordingSettings{
		Enabled:       cfg.Recording.Enabled,
		RetentionDays: cfg.Recording.RetentionDays,
		MaxSessionMB:  cfg.Recording.MaxSessionMB,
		MaxTotalMB:    cfg.Recording.MaxTotalMB,
		MinFreeMB:     cfg.Recording.MinFreeMB,
		DiskPolicy:    cfg.Recording.DiskPolicy,
	})
	if err != nil {
		fatal("recording init error", err)
	}
	recorder.Run(context.Background())

	staticDir := "./public"
	if value := os.Getenv("STATIC_DIR"); value != "" {
		staticDir = value
	}
	dataDir := filepath.Dir(cfg.DataPath)
	server := api.NewServer(stor, auditLogger, clusters, recorder, staticDir, dataDir, cfg.TimeZone)
	backups := backup.New(database, backupDir, cfg.BackupKeep)
	server.SetBackups(backups, cfg.BackupInterval, cfg.BackupAllowDownload)
	server.SetExecLimits(cfg.ExecIdleTimeout, cfg.MaxExecSessionsPerUser)
	server.SetDisabledFeatures(config.DisabledFeatures(api.AllFeatures))
	server.SetPasswordMinLength(cfg.PasswordMinLength)
	server.SetAzureAuthority(os.Getenv("AZURE_AD_AUTHORITY"))
	server.SetKeyExternal(currentKey != nil)
	backups.Run(context.Background(), cfg.BackupInterval, func(info backup.Info, err error) {
		e := models.AuditLog{User: "system", Verb: audit.VerbCreate, ResourceType: audit.KindBackup, ResourceName: info.Name,
			Details: audit.D{"size_bytes": info.SizeBytes}}
		if err != nil {
			e.Outcome, e.Reason, e.ResourceName, e.Details = audit.Failed, "error", "*", audit.D{"error": err.Error()}
		}
		auditLogger.RecordAsync(e)
	})

	// Every request's context derives from base; cancelling it on shutdown
	// ends the WebSockets (shells, logs, events), which http.Server.Shutdown
	// does not wait for.
	base, stopBase := context.WithCancel(context.Background())
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.Router(),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return base },
	}

	go func() {
		slog.Info("server listening", slog.String("addr", httpServer.Addr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal("listen error", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// The pod gets terminationGracePeriodSeconds (30) in all: up to 10 s for
	// requests in flight, then up to 15 s for the open WebSockets to write
	// their end audit and close their recordings, then the database.
	slog.Info("shutdown signal received")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.BeginShutdown()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", slog.Any("error", err))
	}
	stopBase()
	drain, cancelDrain := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelDrain()
	server.Drain(drain)
	if err := database.Close(); err != nil {
		slog.Warn("database close failed", slog.Any("error", err))
	}
	if err := shutdownTracing(drain); err != nil {
		slog.Warn("tracing flush failed", slog.Any("error", err))
	}
	slog.Info("server stopped")
}

// warmClusters connects every cluster at boot, so the first requests don't
// pay the connection cost and pod usage history (sampled per connected
// cluster) starts right away. A failure is logged, not fatal: the console
// still starts and an admin can fix the cluster in the UI.
func warmClusters(ctx context.Context, stor *store.Store, clusters *kube.Registry) {
	list, err := stor.ListClusters(ctx)
	if err != nil {
		return
	}
	for _, c := range list {
		if _, err := clusters.Get(ctx, c.ID); err != nil {
			slog.Warn("cluster unavailable", slog.String("cluster", c.Name), slog.Any("error", err))
			continue
		}
		slog.Info("cluster connected", slog.String("cluster", c.Name))
	}
}

// startRestartHistory stores the container exits the pod informers see and
// prunes them after days. Exits older than that (still on a pod OpenConsole
// meets at start) are not stored at all.
func startRestartHistory(stor *store.Store, clusters *kube.Registry, days int) {
	keep := time.Duration(days) * 24 * time.Hour
	clusters.OnTermination(func(clusterID int, t models.ContainerTermination) {
		if time.Since(t.LastAt) > keep {
			return
		}
		if err := stor.RecordTermination(context.Background(), clusterID, t); err != nil {
			slog.Warn("restart history write failed", slog.Any("error", err))
		}
	})
	go func() {
		for {
			_ = stor.PurgeTerminations(context.Background(), time.Now().Add(-keep))
			time.Sleep(time.Hour)
		}
	}()
}

func fatal(msg string, err error) {
	slog.Error(msg, slog.Any("error", err))
	os.Exit(1)
}

// resetTwoFactor is TWO_FACTOR_RESET_USER: the account's two-factor sign-in
// goes, on every start while the variable is set.
func resetTwoFactor(stor *store.Store, auditLogger *audit.Logger, username string) {
	ctx := context.Background()
	user, err := stor.GetUserByUsername(ctx, username)
	if err != nil {
		slog.Error("TWO_FACTOR_RESET_USER: no such account", slog.String("user", username))
		return
	}
	if err := stor.ResetTwoFactor(ctx, user.ID); err != nil {
		slog.Error("TWO_FACTOR_RESET_USER: reset failed", slog.String("user", username), slog.Any("error", err))
		return
	}
	_ = stor.RevokeAllForUser(ctx, user.ID)
	slog.Warn("TWO_FACTOR_RESET_USER: two-factor sign-in removed; remove the variable, it does this on every start", slog.String("user", username))
	auditLogger.RecordAsync(models.AuditLog{User: "system", Verb: audit.VerbReset, ResourceType: audit.KindTwoFactor,
		ResourceName: username, Details: audit.D{"summary": "TWO_FACTOR_RESET_USER"}})
}
