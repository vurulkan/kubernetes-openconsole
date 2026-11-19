package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port             string
	DataPath         string
	LogRetentionDays int
	// APIKeyReadRetentionDays keeps successful API key reads (list / get /
	// logs) this long; everything else stays LogRetentionDays.
	APIKeyReadRetentionDays int
	AuditPurgeInterval      time.Duration
	TimeZone                string

	// Structured logging (slog) — see internal/logging.
	LogLevel        string // debug|info|warn|error
	LogFormat       string // json|text
	LogOutput       string // stdout|stderr
	LogAddSource    bool
	LogIncludeAudit bool   // mirror audit records to console
	Env             string // deployment env label (dev|prod|...)
	Version         string // build/release version, surfaced in logs

	// PasswordMinLength is the minimum length for local account passwords.
	PasswordMinLength int

	// TrustedProxies (TRUSTED_PROXIES): CIDRs whose X-Forwarded-For is believed.
	TrustedProxies string

	// AllowedOrigins (ALLOWED_ORIGINS) / WSOriginCheck (WS_ORIGIN_CHECK):
	// cross-site browser access, see api/origins.go.
	AllowedOrigins string
	WSOriginCheck  string

	// Encryption key of the stored credentials (see store.Keys): a file
	// (a mounted Secret) or the value itself, base64 of 32 bytes; the
	// previous one during a rotation.
	EncryptionKeyFile, EncryptionKey                 string
	EncryptionKeyPreviousFile, EncryptionKeyPrevious string
	EncryptionKeyLost                                bool
	// TwoFactorResetUser: on every start, remove this account's two-factor sign-in (a locked-out admin).
	TwoFactorResetUser string

	// Database backups (VACUUM INTO): directory ("" = backups next to the
	// database), interval (0 = no scheduled backup), how many to keep.
	BackupDir      string
	BackupInterval time.Duration
	BackupKeep     int
	// BackupAllowDownload (BACKUP_ALLOW_DOWNLOAD): admins may download the
	// copies in Admin → Backups. Off by default and set on the Deployment, so
	// an admin account alone can't turn it on.
	BackupAllowDownload bool

	// Pod shell limits.
	ExecIdleTimeout        time.Duration
	MaxExecSessionsPerUser int

	// RestartHistoryDays keeps container terminations (restart history) this long.
	RestartHistoryDays int

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
		// 0 = never purge
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			retention = parsed
		}
	}

	timeZone := os.Getenv("TIMEZONE")
	if timeZone == "" {
		timeZone = "UTC"
	}

	return Config{
		Port:                    port,
		DataPath:                dataPath,
		LogRetentionDays:        retention,
		APIKeyReadRetentionDays: envIntMin("API_KEY_READ_RETENTION_DAYS", 7, 1),
		AuditPurgeInterval:      12 * time.Hour,
		TimeZone:                timeZone,

		LogLevel:        envOr("LOG_LEVEL", "info"),
		LogFormat:       envOr("LOG_FORMAT", "text"),
		LogOutput:       envOr("LOG_OUTPUT", "stdout"),
		LogAddSource:    envBool("LOG_ADD_SOURCE", false),
		LogIncludeAudit: envBool("LOG_INCLUDE_AUDIT", true),
		Env:             envOr("APP_ENV", ""),
		Version:         envOr("APP_VERSION", ""),

		PasswordMinLength: envIntMin("PASSWORD_MIN_LENGTH", 8, 1),

		TrustedProxies: os.Getenv("TRUSTED_PROXIES"),
		AllowedOrigins: os.Getenv("ALLOWED_ORIGINS"),
		WSOriginCheck:  os.Getenv("WS_ORIGIN_CHECK"),

		EncryptionKeyFile:         os.Getenv("ENCRYPTION_KEY_FILE"),
		EncryptionKey:             os.Getenv("ENCRYPTION_KEY"),
		EncryptionKeyPreviousFile: os.Getenv("ENCRYPTION_KEY_PREVIOUS_FILE"),
		EncryptionKeyPrevious:     os.Getenv("ENCRYPTION_KEY_PREVIOUS"),
		EncryptionKeyLost:         envBool("ENCRYPTION_KEY_LOST", false),
		TwoFactorResetUser:        strings.TrimSpace(os.Getenv("TWO_FACTOR_RESET_USER")),

		BackupDir:              os.Getenv("BACKUP_DIR"),
		BackupInterval:         envDurationMin("BACKUP_INTERVAL", 24*time.Hour, 0),
		BackupKeep:             envIntMin("BACKUP_KEEP", 7, 1),
		BackupAllowDownload:    envBool("BACKUP_ALLOW_DOWNLOAD", false),
		ExecIdleTimeout:        envDurationMin("EXEC_IDLE_TIMEOUT", 5*time.Minute, 30*time.Second),
		MaxExecSessionsPerUser: envIntMin("MAX_EXEC_SESSIONS_PER_USER", 3, 0),
		RestartHistoryDays:     envIntMin("RESTART_HISTORY_RETENTION_DAYS", 30, 1),

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

// ReadKey returns the key from file (preferred) or value: base64 of 32
// bytes. Both empty = nil (no key).
func ReadKey(file, value string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		value = string(b)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("the key must be base64 of 32 bytes (openssl rand -base64 32)")
	}
	return key, nil
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

// envDurationMin parses a Go duration ("10m", "90s"), falling back when it is
// unset, malformed or below min.
func envDurationMin(key string, fallback, min time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min {
		return fallback
	}
	return d
}

// DisabledFeatures reads FEATURE_<NAME>=false for each known feature name.
func DisabledFeatures(names []string) []string {
	var off []string
	for _, n := range names {
		if !envBool("FEATURE_"+strings.ToUpper(n), true) {
			off = append(off, n)
		}
	}
	return off
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
