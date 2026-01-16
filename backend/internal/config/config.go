package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port              string
	DataPath          string
	LogRetentionDays  int
	AuditPurgeInterval time.Duration
	TimeZone          string
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
		Port:              port,
		DataPath:          dataPath,
		LogRetentionDays:  retention,
		AuditPurgeInterval: 12 * time.Hour,
		TimeZone:          timeZone,
	}
}
