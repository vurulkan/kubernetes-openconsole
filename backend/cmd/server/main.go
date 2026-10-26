package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k8s-dashboard/backend/internal/api"
	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
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
	auth.MinPasswordLength = cfg.PasswordMinLength
	shutdownTracing, err := telemetry.Setup(context.Background(), cfg.Version, cfg.Env)
	if err != nil {
		slog.Warn("tracing disabled: exporter setup failed", slog.Any("error", err))
	}
	api.SetExecLimits(cfg.ExecIdleTimeout, cfg.MaxExecSessionsPerUser)
	api.SetDisabledFeatures(config.DisabledFeatures(api.AllFeatures))
	if v := os.Getenv("AZURE_AD_AUTHORITY"); v != "" {
		auth.AzureAuthority = strings.TrimRight(v, "/")
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

	slog.Info("starting openconsole",
		slog.String("port", cfg.Port),
		slog.String("data_path", cfg.DataPath),
		slog.String("timezone", cfg.TimeZone),
		slog.String("log_format", cfg.LogFormat),
		slog.String("log_level", cfg.LogLevel),
	)

	database, err := db.Open(cfg.DataPath)
	if err != nil {
		fatal("db error", err)
	}

	stor, err := store.New(database.Conn)
	if err != nil {
		fatal("store error", err)
	}

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
	audit.SetMetricHook(api.MetricsAuditIncr)
	if err := auditLogger.UpgradeLegacy(context.Background()); err != nil {
		slog.Warn("audit upgrade failed; older rows keep the pre-2.17 format", slog.Any("error", err))
	}
	auditLogger.StartRetention(context.Background(), cfg.LogRetentionDays, cfg.AuditPurgeInterval)

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
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.Router(),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
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

	slog.Info("shutdown signal received")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", slog.Any("error", err))
	}
	if err := shutdownTracing(ctx); err != nil {
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
