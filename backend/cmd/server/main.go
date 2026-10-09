package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
)

func main() {
	cfg := config.Load()
	auth.MinPasswordLength = cfg.PasswordMinLength
	api.SetExecLimits(cfg.ExecIdleTimeout, cfg.MaxExecSessionsPerUser)

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
	warmDefaultCluster(context.Background(), stor, clusters)

	auditLogger := audit.New(stor)
	auditLogger.SetConsoleMirror(cfg.LogIncludeAudit)
	audit.SetMetricHook(api.MetricsAuditIncr)
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
	slog.Info("server stopped")
}

// warmDefaultCluster connects the default cluster at boot so the first
// requests don't pay the connection cost. A failure is logged, not fatal:
// the console still starts and an admin can fix the cluster in the UI.
func warmDefaultCluster(ctx context.Context, stor *store.Store, clusters *kube.Registry) {
	c, err := stor.GetActiveCluster(ctx)
	if err != nil || c == nil {
		return
	}
	if _, err := clusters.Get(ctx, c.ID); err != nil {
		slog.Warn("default cluster unavailable", slog.String("cluster", c.Name), slog.Any("error", err))
		return
	}
	slog.Info("default cluster connected", slog.String("cluster", c.Name))
}

func fatal(msg string, err error) {
	slog.Error(msg, slog.Any("error", err))
	os.Exit(1)
}
