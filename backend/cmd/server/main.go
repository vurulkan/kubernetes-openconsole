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
	"k8s-dashboard/backend/internal/store"
)

func main() {
	cfg := config.Load()

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

	kubeManager := kube.NewManager()
	if creds, err := stor.GetKubeCredentials(context.Background()); err == nil && creds.Active {
		if err := kubeManager.ApplyCredentials(creds); err == nil {
			_ = kubeManager.Start(context.Background())
		}
	}

	auditLogger := audit.New(stor)
	auditLogger.SetConsoleMirror(cfg.LogIncludeAudit)
	audit.SetMetricHook(api.MetricsAuditIncr)
	auditLogger.StartRetention(context.Background(), cfg.LogRetentionDays, cfg.AuditPurgeInterval)

	staticDir := "./public"
	if value := os.Getenv("STATIC_DIR"); value != "" {
		staticDir = value
	}
	dataDir := filepath.Dir(cfg.DataPath)
	server := api.NewServer(stor, auditLogger, kubeManager, staticDir, dataDir, cfg.TimeZone)
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

func fatal(msg string, err error) {
	slog.Error(msg, slog.Any("error", err))
	os.Exit(1)
}
