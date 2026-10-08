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

	// Pod exec session recording. These only seed recording_settings on
	// first boot (except Dir); afterwards the admin UI owns the values.
	Recording RecordingConfig
}

type RecordingConfig struct {
	Enabled       bool
	Dir           string // "" → <dir of DATA_PATH>/recordings
	RetentionDays int    // 0 = never purge
	MaxSessionMB  int
	MaxTotalMB    int
	MinFreeMB     int
	DiskPolicy    string // evict_oldest | stop
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

		Recording: RecordingConfig{
			Enabled:       envBool("SESSION_RECORDING_ENABLED", true),
			Dir:           os.Getenv("SESSION_RECORDING_DIR"),
			RetentionDays: envIntMin("SESSION_RECORDING_RETENTION_DAYS", 30, 0),
			MaxSessionMB:  envIntMin("SESSION_RECORDING_MAX_SIZE_MB", 10, 1),
			MaxTotalMB:    envIntMin("SESSION_RECORDING_MAX_TOTAL_MB", 2048, 1),
			MinFreeMB:     envIntMin("SESSION_RECORDING_MIN_FREE_MB", 512, 0),
			DiskPolicy:    envOr("SESSION_RECORDING_DISK_POLICY", "evict_oldest"),
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntMin parses an integer env var, falling back when it is unset,
// malformed or below min.
func envIntMin(key string, fallback, min int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil || parsed < min {
		return fallback
	}
	return parsed
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
