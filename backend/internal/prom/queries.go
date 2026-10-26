package prom

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Ranges Prometheus answers, with their step. The rate window is
// max(5m, 4 × step) so a 60 s scrape interval still has samples in it.
var Ranges = map[string]struct{ Span, Step time.Duration }{
	"1h":  {time.Hour, 30 * time.Second},
	"6h":  {6 * time.Hour, 2 * time.Minute},
	"24h": {24 * time.Hour, 5 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 30 * time.Minute},
}

func window(step time.Duration) string {
	w := 4 * step
	if w < 5*time.Minute {
		w = 5 * time.Minute
	}
	return fmt.Sprintf("%ds", int(w/time.Second))
}

// quote makes a PromQL string literal; Kubernetes names can't break out of it anyway.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Selector builds the label matchers for container series of the given pods.
// podRegex is an RE2 pattern (anchored by Prometheus).
func (c *Client) selector(namespace, podRegex string) string {
	m := []string{
		"namespace=" + quote(namespace),
		"pod=~" + quote(podRegex),
		`container!=""`,
		`container!="POD"`,
	}
	if c.cfg.ClusterLabel != "" && c.cfg.ClusterValue != "" {
		m = append(m, c.cfg.ClusterLabel+"="+quote(c.cfg.ClusterValue))
	}
	return "{" + strings.Join(m, ",") + "}"
}

// PodRegex matches one pod.
func PodRegex(pod string) string { return regexp.QuoteMeta(pod) }

// DeploymentRegex matches a Deployment's pods: <name>-<pod-template-hash>-<5 chars>,
// for the given ReplicaSet hashes (current and old revisions).
func DeploymentRegex(name string, hashes []string) string {
	if len(hashes) == 0 {
		return regexp.QuoteMeta(name) + `-[a-z0-9]+-[a-z0-9]{5}`
	}
	q := make([]string, len(hashes))
	for i, h := range hashes {
		q[i] = regexp.QuoteMeta(h)
	}
	return regexp.QuoteMeta(name) + "-(" + strings.Join(q, "|") + `)-[a-z0-9]{5}`
}

// StatefulSetRegex matches <name>-<ordinal>.
func StatefulSetRegex(name string) string { return regexp.QuoteMeta(name) + `-[0-9]+` }

// DaemonSetRegex matches <name>-<5 chars>.
func DaemonSetRegex(name string) string { return regexp.QuoteMeta(name) + `-[a-z0-9]{5}` }

// Point matches kube.Point's JSON (CPU in millicores, memory in bytes).
type Point struct {
	T   int64 `json:"t"`
	CPU int64 `json:"cpu"`
	Mem int64 `json:"memory"`
}

// History returns CPU and memory of the pods podRegex matches, summed.
// "max by" per container guards against setups that scrape cAdvisor twice.
func (c *Client) History(ctx context.Context, namespace, podRegex, rng string, now time.Time) ([]Point, error) {
	r, ok := Ranges[rng]
	if !ok {
		r = Ranges["1h"]
	}
	sel := c.selector(namespace, podRegex)
	cpuQ := fmt.Sprintf("sum(max by (namespace, pod, container) (rate(container_cpu_usage_seconds_total%s[%s])))", sel, window(r.Step))
	memQ := fmt.Sprintf("sum(max by (namespace, pod, container) (container_memory_working_set_bytes%s))", sel)
	start := now.Add(-r.Span)
	cpu, err := c.QueryRange(ctx, cpuQ, start, now, r.Step)
	if err != nil {
		return nil, err
	}
	mem, err := c.QueryRange(ctx, memQ, start, now, r.Step)
	if err != nil {
		return nil, err
	}
	byT := map[int64]*Point{}
	at := func(t int64) *Point {
		if byT[t] == nil {
			byT[t] = &Point{T: t}
		}
		return byT[t]
	}
	for _, s := range first(cpu) {
		at(s.T).CPU = int64(s.V * 1000)
	}
	for _, s := range first(mem) {
		at(s.T).Mem = int64(s.V)
	}
	out := make([]Point, 0, len(byT))
	for _, p := range byT {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out, nil
}

func first(series [][]Sample) []Sample {
	if len(series) == 0 {
		return nil
	}
	return series[0]
}

// Step is one diagnostic check of the test button.
type Step struct {
	ID     string `json:"id"`     // reach | auth | api | container_metrics | clusters | duplicates
	Status string `json:"status"` // ok | warn | fail
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Diagnosis is what the test button shows; it stops at the first failure.
type Diagnosis struct {
	OK            bool     `json:"ok"`
	Steps         []Step   `json:"steps"`
	ClusterValues []string `json:"clusterValues,omitempty"`
}

// Diagnose checks, in order: the address answers, we are allowed in, it is a
// Prometheus API, there are container metrics (for the cluster filter), a
// multi-cluster Prometheus has a filter, and cAdvisor isn't scraped twice.
func (c *Client) Diagnose(ctx context.Context) Diagnosis {
	var d Diagnosis
	fail := func(id, reason, detail string) Diagnosis {
		d.Steps = append(d.Steps, Step{ID: id, Status: "fail", Reason: reason, Detail: detail})
		return d
	}
	if _, _, err := c.Query(ctx, "up"); err != nil {
		id, reason := classify(err)
		return fail(id, reason, err.Error())
	}
	d.Steps = append(d.Steps, Step{ID: "reach", Status: "ok"}, Step{ID: "auth", Status: "ok"}, Step{ID: "api", Status: "ok"})

	label := c.cfg.ClusterLabel
	if label == "" {
		label = "cluster"
	}
	values, _ := c.LabelValues(ctx, label)
	d.ClusterValues = values

	filter := `{container!="",container!="POD"`
	if c.cfg.ClusterLabel != "" && c.cfg.ClusterValue != "" {
		filter += "," + c.cfg.ClusterLabel + "=" + quote(c.cfg.ClusterValue)
	}
	filter += "}"
	n, _, err := c.Query(ctx, "count(container_memory_working_set_bytes"+filter+")")
	if err != nil {
		return fail("container_metrics", "query_failed", err.Error())
	}
	if n == 0 {
		return fail("container_metrics", "no_container_metrics", "")
	}
	d.Steps = append(d.Steps, Step{ID: "container_metrics", Status: "ok", Detail: fmt.Sprintf("%.0f", n)})

	switch {
	case len(values) > 1 && c.cfg.ClusterValue == "":
		d.Steps = append(d.Steps, Step{ID: "clusters", Status: "warn", Reason: "multiple_clusters", Detail: strings.Join(values, ", ")})
	case c.cfg.ClusterValue != "" && !contains(values, c.cfg.ClusterValue):
		d.Steps = append(d.Steps, Step{ID: "clusters", Status: "warn", Reason: "filter_value_unknown", Detail: strings.Join(values, ", ")})
	default:
		d.Steps = append(d.Steps, Step{ID: "clusters", Status: "ok"})
	}

	dup, _, err := c.Query(ctx, "count(count by (namespace, pod, container) (container_memory_working_set_bytes"+filter+") > 1)")
	if err == nil && dup > 0 {
		d.Steps = append(d.Steps, Step{ID: "duplicates", Status: "warn", Reason: "duplicate_series", Detail: fmt.Sprintf("%.0f", dup)})
	} else {
		d.Steps = append(d.Steps, Step{ID: "duplicates", Status: "ok"})
	}
	d.OK = true
	return d
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// classify maps a first-query error to the failing step and a reason the UI translates.
func classify(err error) (step, reason string) {
	var se *StatusError
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case apierrors.IsForbidden(err):
		return "auth", "proxy_forbidden"
	case apierrors.IsNotFound(err), apierrors.IsServiceUnavailable(err):
		return "reach", "service_not_found"
	case errors.As(err, &se) && (se.Code == 401 || se.Code == 403):
		return "auth", "unauthorized"
	case errors.As(err, &se):
		return "api", fmt.Sprintf("http_%d", se.Code)
	case errors.Is(err, ErrNotPrometheus):
		return "api", "not_prometheus"
	case errors.As(err, &dnsErr):
		return "reach", "dns"
	case strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "tls:"):
		return "reach", "tls"
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "reach", "timeout"
	default:
		return "reach", "unreachable"
	}
}
