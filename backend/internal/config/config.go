package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port               string
	DataPath           string
	LogRetentionDays   int
	AuditPurgeInterval time.Duration
	TimeZone           string

	// Structured logging (slog) — see internal/logging.
	LogLevel        string // debug|info|warn|error
	LogFormat       string // json|text
	LogOutput       string // stdout|stderr
	LogAddSource    bool
	LogIncludeAudit bool   // mirror audit records to console
	Env             string // deployment env label (dev|prod|...)
	Version         string // build/release version, surfaced in logs
}

func Load() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataPath := os.Getenv("DATA_PATH")
	if dataPath == "" {
		dataPath = "./data/app.db"
	}

	retention := 30
	if value := os.Getenv("LOG_RETENTION_DAYS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			retention = parsed
		}
	}

	timeZone := os.Getenv("TIMEZONE")
	if timeZone == "" {
		timeZone = "UTC"
	}

	return Config{
		Port:               port,
		DataPath:           dataPath,
		LogRetentionDays:   retention,
		AuditPurgeInterval: 12 * time.Hour,
		TimeZone:           timeZone,

		LogLevel:        envOr("LOG_LEVEL", "info"),
		LogFormat:       envOr("LOG_FORMAT", "text"),
		LogOutput:       envOr("LOG_OUTPUT", "stdout"),
		LogAddSource:    envBool("LOG_ADD_SOURCE", false),
		LogIncludeAudit: envBool("LOG_INCLUDE_AUDIT", true),
		Env:             envOr("APP_ENV", ""),
		Version:         envOr("APP_VERSION", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false
	default:
		return fallback
	}
}
