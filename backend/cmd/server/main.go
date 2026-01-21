package main

import (
	"context"
	"log"
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
	"k8s-dashboard/backend/internal/store"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg.DataPath)
	if err != nil {
		log.Fatalf("db error: %v", err)
	}

	store, err := store.New(database.Conn)
	if err != nil {
		log.Fatalf("store error: %v", err)
	}

	defaultHash, err := auth.HashPassword("admin")
	if err != nil {
		log.Fatalf("hash error: %v", err)
	}
	if err := store.EnsureDefaultAdmin(context.Background(), defaultHash); err != nil {
		log.Fatalf("admin seed error: %v", err)
	}

	kubeManager := kube.NewManager()
	if creds, err := store.GetKubeCredentials(context.Background()); err == nil && creds.Active {
		if err := kubeManager.ApplyCredentials(creds); err == nil {
			_ = kubeManager.Start(context.Background())
		}
	}

	auditLogger := audit.New(store)
	auditLogger.StartRetention(context.Background(), cfg.LogRetentionDays, cfg.AuditPurgeInterval)

	staticDir := "./public"
	if value := os.Getenv("STATIC_DIR"); value != "" {
		staticDir = value
	}
	dataDir := filepath.Dir(cfg.DataPath)
	server := api.NewServer(store, auditLogger, kubeManager, staticDir, dataDir, cfg.TimeZone)
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.Router(),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("server listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
