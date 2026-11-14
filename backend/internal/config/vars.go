package config

// Var documents one environment variable the server reads. cmd/docgen turns
// Vars into the docs site's Environment variables page, and vars_test.go fails
// when the backend reads a variable that is not listed here. Feature flags
// (FEATURE_<NAME>) are listed from api.AllFeatures instead.
type Var struct {
	Name        string
	Section     string // one of Sections
	Default     string // as the server applies it when unset; "" = none
	Description string // Markdown, one paragraph
}

// Sections orders the groups on the docs page.
var Sections = []string{"Core", "Logging", "Tracing (OpenTelemetry)", "Security and limits", "Sign-in", "Session recording"}

// Vars is every environment variable the backend reads, in page order.
var Vars = []Var{
	{"PORT", "Core", "8080", "HTTP port the server listens on (API, UI, `/metrics`, probes)."},
	{"DATA_PATH", "Core", "./data/app.db", "SQLite database file. Must be on a persistent volume; the directory also holds session recordings unless `SESSION_RECORDING_DIR` is set."},
	{"STATIC_DIR", "Core", "./public", "Directory of the React build the server serves."},
	{"TIMEZONE", "Core", "UTC", "Time zone of audit log timestamps in the UI and CSV export."},
	{"LOG_RETENTION_DAYS", "Core", "30", "How long audit events are kept in the database; older ones are purged automatically."},
	{"API_KEY_READ_RETENTION_DAYS", "Core", "7", "How long **successful reads made with an API key** (`list`, `get`, `logs`, `view_yaml`, `view_overview`) are kept; they are most of an agent's audit volume. Writes, denials, failures, `pod.exec` and `api_key.*` events stay for `LOG_RETENTION_DAYS`. Console / Elastic lines are not affected."},
	{"RESTART_HISTORY_RETENTION_DAYS", "Core", "30", "How long container exits (restart history) are kept."},
	{"MAX_REPLICAS", "Core", "100", "Highest replica count the Scale endpoint accepts for Deployments and StatefulSets."},

	{"LOG_FORMAT", "Logging", "text", "`ecs` (Elastic Common Schema, nested JSON; use it for Elastic), `json` (flat JSON with short field names) or `text` (for reading by eye)."},
	{"LOG_LEVEL", "Logging", "info", "`debug`, `info`, `warn` or `error`. Successful health probes and `/metrics` scrapes are logged at `debug` only."},
	{"LOG_OUTPUT", "Logging", "stdout", "`stdout` or `stderr`."},
	{"LOG_ADD_SOURCE", "Logging", "false", "Add the source file and line to every record (`log.origin.*` in ECS)."},
	{"LOG_INCLUDE_AUDIT", "Logging", "true", "Write every audit event to stdout as well, one line per action, with the request id of its HTTP request line. With `false` the database still has them."},
	{"APP_ENV", "Logging", "", "Environment label on every log record (`service.environment`) and trace (`deployment.environment`), e.g. `prod`."},
	{"APP_VERSION", "Logging", "the build version", "Overrides the version on log records and traces (`service.version`), e.g. for a canary."},

	{"OTEL_EXPORTER_OTLP_ENDPOINT", "Tracing (OpenTelemetry)", "", "OTLP/HTTP receiver, e.g. `http://otel-collector.observability:4318`. Setting this or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` turns tracing on; the other `OTEL_*` variables of the OpenTelemetry specification (headers, sampler, resource attributes) apply as well."},
	{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "Tracing (OpenTelemetry)", "", "OTLP/HTTP endpoint for traces only (full URL, including `/v1/traces`)."},
	{"OTEL_SERVICE_NAME", "Tracing (OpenTelemetry)", "openconsole", "`service.name` of the traces."},

	{"PASSWORD_MIN_LENGTH", "Security and limits", "8", "Minimum length of local passwords (create, change, admin reset). Passwords are also capped at 72 bytes (bcrypt)."},
	{"EXEC_IDLE_TIMEOUT", "Security and limits", "5m", "A pod shell with no input for this long is closed. Go duration (`90s`, `10m`, `1h`); minimum `30s`."},
	{"MAX_EXEC_SESSIONS_PER_USER", "Security and limits", "3", "Open pod shells per user; one more is refused with 429 and audited as `pod.exec` / `rate_limited`. `0` = unlimited."},

	{"AZURE_AD_AUTHORITY", "Sign-in", "https://login.microsoftonline.com", "Microsoft Entra ID sign-in host for national clouds, e.g. `https://login.microsoftonline.us` or `https://login.chinacloudapi.cn`."},

	{"SESSION_RECORDING_DIR", "Session recording", "<dir of DATA_PATH>/recordings", "Where `.cast` files are written. Read on every start."},
	{"SESSION_RECORDING_ENABLED", "Session recording", "true", "Record new pod shell sessions. Seeds Admin → Recordings on the first start only, like the variables below; after that the setting in the UI wins."},
	{"SESSION_RECORDING_RETENTION_DAYS", "Session recording", "30", "Daily purge of older recordings; `0` = never. First start only."},
	{"SESSION_RECORDING_MAX_SIZE_MB", "Session recording", "10", "Per-session cap; past it the recording stops and is flagged truncated. First start only."},
	{"SESSION_RECORDING_MAX_TOTAL_MB", "Session recording", "2048", "Quota for all recordings together. First start only."},
	{"SESSION_RECORDING_MIN_FREE_MB", "Session recording", "512", "Free space always left on the recordings volume. First start only."},
	{"SESSION_RECORDING_DISK_POLICY", "Session recording", "evict_oldest", "What happens at the quota: `evict_oldest` deletes the oldest recordings, `stop` stops recording new sessions. First start only."},
}
