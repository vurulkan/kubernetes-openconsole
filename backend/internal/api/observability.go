package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Security headers middleware ─────────────────────────────────────────────

// securityHeaders adds hardening headers appropriate for a single-origin app.
// CSP allows self plus inline/font/img data because the frontend bundles its
// own styles and loads Google Fonts and uses a dynamic logo URL.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), interest-cohort=()")
		if h.Get("Content-Security-Policy") == "" {
			// Monaco editor (YAML edit modal, 2.6.0+) loads its chunks from
			// jsdelivr by default. If an operator deploys in an air-gapped
			// network, point @monaco-editor/react.loader.config() at a
			// self-hosted path and tighten this CSP back to 'self'.
			// 'wasm-unsafe-eval' lets the bundled asciinema-player compile its
			// WebAssembly terminal (recording playback, 2.11.0+); it does not
			// allow JS eval.
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "+
					"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "+
					"font-src 'self' https://fonts.gstatic.com data:; "+
					"img-src 'self' data: blob:; "+
					"connect-src 'self' ws: wss: https://cdn.jsdelivr.net; "+
					"worker-src 'self' blob:; "+
					"frame-ancestors 'none'; "+
					"base-uri 'self'; "+
					"form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

// ─── Login brute-force / rate limit ──────────────────────────────────────────

type loginAttempt struct {
	fails    int
	lockedAt time.Time
}

type loginGate struct {
	mu       sync.Mutex
	byIPUser map[string]*loginAttempt
}

var loginGateSingleton = &loginGate{byIPUser: map[string]*loginAttempt{}}

// Thresholds. Picked small enough to deter credential stuffing but large
// enough to not frustrate a typo-prone human.
const (
	loginFailsBeforeLock = 5
	loginLockWindow      = 5 * time.Minute
)

// checkLogin returns (allowed, retryAfterSeconds). It should be called BEFORE
// the credential check.
func (g *loginGate) check(ipUser string) (bool, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.byIPUser[ipUser]
	if !ok {
		return true, 0
	}
	if a.fails < loginFailsBeforeLock {
		return true, 0
	}
	// Locked: check if window elapsed.
	remain := loginLockWindow - time.Since(a.lockedAt)
	if remain <= 0 {
		delete(g.byIPUser, ipUser)
		return true, 0
	}
	return false, int(remain.Seconds()) + 1
}

func (g *loginGate) recordFailure(ipUser string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.byIPUser[ipUser]
	if !ok {
		a = &loginAttempt{}
		g.byIPUser[ipUser] = a
	}
	a.fails++
	if a.fails == loginFailsBeforeLock {
		a.lockedAt = time.Now()
	}
}

func (g *loginGate) recordSuccess(ipUser string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.byIPUser, ipUser)
}

// LoginGate exposes the singleton for handler use.
func LoginGate() *loginGate { return loginGateSingleton }

// ─── Prometheus-compatible /metrics (minimal, zero-dep) ──────────────────────
// We ship a hand-rolled exporter rather than pulling the full prometheus/client_golang
// just so one page can be scraped. It emits the exposition format cleanly.

type httpMetrics struct {
	requestsTotal       atomic.Int64
	requestsByStatus    sync.Map // map[string]*atomic.Int64 (status bucket -> count)
	durationSumMs       atomic.Int64
	durationCount       atomic.Int64
	auditEventsTotal    atomic.Int64
	execSessionsTotal   atomic.Int64
	wsLogStreamsStarted atomic.Int64
	deployActionsTotal  atomic.Int64
	// requestsByCluster counts authenticated API requests per cluster name.
	requestsByCluster sync.Map // map[string]*atomic.Int64
}

var metricsStore = &httpMetrics{}

// metricExecActive is the number of open pod shells.
var metricExecActive atomic.Int64

// clusterStatusFn reports cluster name → connected for /metrics; set by
// NewServer from the cluster registry.
var clusterStatusFn func() map[string]bool

func metricsRecordClusterRequest(cluster string) {
	if cluster == "" {
		return
	}
	v, _ := metricsStore.requestsByCluster.LoadOrStore(cluster, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// promLabel escapes a Prometheus label value.
func promLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func metricsRecordRequest(status int, durationMs int64) {
	metricsStore.requestsTotal.Add(1)
	metricsStore.durationSumMs.Add(durationMs)
	metricsStore.durationCount.Add(1)
	bucket := "2xx"
	switch {
	case status >= 500:
		bucket = "5xx"
	case status >= 400:
		bucket = "4xx"
	case status >= 300:
		bucket = "3xx"
	}
	v, _ := metricsStore.requestsByStatus.LoadOrStore(bucket, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// Public hooks so other files can bump counters.
func MetricsAuditIncr()     { metricsStore.auditEventsTotal.Add(1) }
func MetricsExecIncr()      { metricsStore.execSessionsTotal.Add(1) }
func MetricsLogStreamIncr() { metricsStore.wsLogStreamsStarted.Add(1) }
func MetricsDeployAction()  { metricsStore.deployActionsTotal.Add(1) }

// MetricDoc describes one series of GET /metrics. Metrics is the only place
// their help text lives: handleMetrics writes it, cmd/docgen turns it into the
// docs site's Metrics page, and observability_test.go fails on a series
// missing from it.
type MetricDoc struct {
	Name, Type, Help string
	Labels           []string
}

var Metrics = []MetricDoc{
	{"openconsole_http_requests_total", "counter", "HTTP requests served.", nil},
	{"openconsole_http_requests_status_total", "counter", "HTTP requests served, by status class (2xx, 3xx, 4xx, 5xx).", []string{"status"}},
	{"openconsole_http_request_duration_ms_sum", "counter", "Sum of request durations in milliseconds.", nil},
	{"openconsole_http_request_duration_ms_count", "counter", "Count of observed requests used for duration stats.", nil},
	{"openconsole_audit_events_total", "counter", "Audit log entries recorded.", nil},
	{"openconsole_pod_exec_sessions_total", "counter", "Pod exec sessions started.", nil},
	{"openconsole_pod_log_streams_total", "counter", "Pod log WebSocket streams started.", nil},
	{"openconsole_deployment_actions_total", "counter", "Deployment restart or scale actions attempted.", nil},
	{"openconsole_pod_exec_active", "gauge", "Pod exec sessions currently open.", nil},
	{"openconsole_cluster_requests_total", "counter", "Authenticated API requests per cluster.", []string{"cluster"}},
	{"openconsole_cluster_connected", "gauge", "1 when OpenConsole holds a live connection to the cluster.", []string{"cluster"}},
}

// metricHeader writes the # HELP / # TYPE lines of a metric from Metrics.
func metricHeader(w http.ResponseWriter, name string) {
	for _, m := range Metrics {
		if m.Name == name {
			_, _ = w.Write([]byte("# HELP " + name + " " + m.Help + "\n# TYPE " + name + " " + m.Type + "\n"))
			return
		}
	}
}

func writeMetric(w http.ResponseWriter, name string, value int64, labels string) {
	metricHeader(w, name)
	line := name
	if labels != "" {
		line += "{" + labels + "}"
	}
	line += " " + strconv.FormatInt(value, 10) + "\n"
	_, _ = w.Write([]byte(line))
}

func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetric(w, "openconsole_http_requests_total", metricsStore.requestsTotal.Load(), "")

	metricsStore.requestsByStatus.Range(func(key, value any) bool {
		bucket := key.(string)
		count := value.(*atomic.Int64).Load()
		_, _ = w.Write([]byte("openconsole_http_requests_status_total{status=\"" + bucket + "\"} " +
			strconv.FormatInt(count, 10) + "\n"))
		return true
	})

	sum := metricsStore.durationSumMs.Load()
	count := metricsStore.durationCount.Load()
	writeMetric(w, "openconsole_http_request_duration_ms_sum", sum, "")
	writeMetric(w, "openconsole_http_request_duration_ms_count", count, "")

	writeMetric(w, "openconsole_audit_events_total", metricsStore.auditEventsTotal.Load(), "")
	writeMetric(w, "openconsole_pod_exec_sessions_total", metricsStore.execSessionsTotal.Load(), "")
	writeMetric(w, "openconsole_pod_log_streams_total", metricsStore.wsLogStreamsStarted.Load(), "")
	writeMetric(w, "openconsole_deployment_actions_total", metricsStore.deployActionsTotal.Load(), "")
	writeMetric(w, "openconsole_pod_exec_active", metricExecActive.Load(), "")

	metricHeader(w, "openconsole_cluster_requests_total")
	metricsStore.requestsByCluster.Range(func(key, value any) bool {
		_, _ = w.Write([]byte("openconsole_cluster_requests_total{cluster=\"" + promLabel(key.(string)) + "\"} " +
			strconv.FormatInt(value.(*atomic.Int64).Load(), 10) + "\n"))
		return true
	})
	if fn := clusterStatusFn; fn != nil {
		metricHeader(w, "openconsole_cluster_connected")
		for name, up := range fn() {
			v := "0"
			if up {
				v = "1"
			}
			_, _ = w.Write([]byte("openconsole_cluster_connected{cluster=\"" + promLabel(name) + "\"} " + v + "\n"))
		}
	}
}
