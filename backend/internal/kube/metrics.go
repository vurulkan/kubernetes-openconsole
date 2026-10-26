package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
)

// Pod CPU / memory from metrics-server, sampled every 30 s for every pod of a
// connected cluster and kept in memory: the last hour at 30 s resolution and
// up to 24 h as 5-minute averages. Restarting OpenConsole starts over;
// longer, persistent history comes from Prometheus.

const (
	sampleInterval = 30 * time.Second
	fineWindow     = time.Hour
	coarseStep     = 5 * time.Minute
	historyWindow  = 24 * time.Hour
)

// Usage is CPU in millicores and memory (working set) in bytes.
type Usage struct {
	CPU int64 `json:"cpu"`
	Mem int64 `json:"memory"`
}

// PodUsage is one pod's latest sample.
type PodUsage struct {
	Namespace  string           `json:"-"`
	Name       string           `json:"name"`
	Owner      string           `json:"owner,omitempty"` // "Deployment/web", "StatefulSet/db", "DaemonSet/agent"
	Usage                       // pod total
	Containers map[string]Usage `json:"containers"`
}

// Point is one sample (or 5-minute average) of a pod or a deployment.
type Point struct {
	T int64 `json:"t"` // unix seconds
	Usage
}

type series struct {
	owner    string
	fine     []Point
	coarse   []Point
	bucket   int64 // start of the 5-minute bucket being averaged
	sum      Usage
	n        int64
	lastSeen int64
}

func (s *series) add(t int64, u Usage) {
	s.fine = append(s.fine, Point{T: t, Usage: u})
	for len(s.fine) > 0 && t-s.fine[0].T > int64(fineWindow/time.Second) {
		s.fine = s.fine[1:]
	}
	b := t - t%int64(coarseStep/time.Second)
	if b != s.bucket && s.n > 0 {
		s.coarse = append(s.coarse, Point{T: s.bucket, Usage: Usage{CPU: s.sum.CPU / s.n, Mem: s.sum.Mem / s.n}})
		s.sum, s.n = Usage{}, 0
	}
	for len(s.coarse) > 0 && t-s.coarse[0].T > int64(historyWindow/time.Second) {
		s.coarse = s.coarse[1:]
	}
	s.bucket = b
	s.sum.CPU += u.CPU
	s.sum.Mem += u.Mem
	s.n++
	s.lastSeen = t
}

// points returns the samples newer than from: 5-minute averages where the
// fine samples no longer reach, then the fine samples.
func (s *series) points(from int64) []Point {
	var out []Point
	firstFine := int64(1<<62 - 1)
	if len(s.fine) > 0 {
		firstFine = s.fine[0].T
	}
	for _, p := range s.coarse {
		if p.T >= from && p.T < firstFine {
			out = append(out, p)
		}
	}
	for _, p := range s.fine {
		if p.T >= from {
			out = append(out, p)
		}
	}
	return out
}

// MetricsSampler keeps one cluster's pod usage. fetch is metrics-server in
// production and a stub in tests.
type MetricsSampler struct {
	fetch func(ctx context.Context) ([]PodUsage, error)

	mu        sync.RWMutex
	latest    map[string]map[string]PodUsage // namespace → pod → usage
	series    map[string]*series             // namespace/pod
	updatedAt time.Time
	available bool
	reason    string
	stop      chan struct{}
}

func NewMetricsSampler(fetch func(ctx context.Context) ([]PodUsage, error)) *MetricsSampler {
	return &MetricsSampler{fetch: fetch, series: map[string]*series{}, stop: make(chan struct{})}
}

func newMetricsServerSampler(client kubernetes.Interface) *MetricsSampler {
	return NewMetricsSampler(func(ctx context.Context) ([]PodUsage, error) {
		raw, err := client.CoreV1().RESTClient().Get().AbsPath("/apis/metrics.k8s.io/v1beta1/pods").DoRaw(ctx)
		if err != nil {
			return nil, err
		}
		return parsePodMetrics(raw)
	})
}

// parsePodMetrics decodes a metrics.k8s.io PodMetricsList without pulling in
// the metrics client module.
func parsePodMetrics(raw []byte) ([]PodUsage, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Containers []struct {
				Name  string            `json:"name"`
				Usage map[string]string `json:"usage"`
			} `json:"containers"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode pod metrics: %w", err)
	}
	out := make([]PodUsage, 0, len(list.Items))
	for _, it := range list.Items {
		p := PodUsage{
			Namespace:  it.Metadata.Namespace,
			Name:       it.Metadata.Name,
			Owner:      ownerFromLabels(it.Metadata.Name, it.Metadata.Labels),
			Containers: map[string]Usage{},
		}
		for _, c := range it.Containers {
			u := Usage{CPU: quantity(c.Usage["cpu"], true), Mem: quantity(c.Usage["memory"], false)}
			p.Containers[c.Name] = u
			p.CPU += u.CPU
			p.Mem += u.Mem
		}
		out = append(out, p)
	}
	return out, nil
}

func quantity(s string, milli bool) int64 {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	if milli {
		return q.MilliValue()
	}
	return q.Value()
}

// ownerFromLabels names a pod's workload from its name and labels (metrics-server
// returns no owner references): a Deployment's pods are <deployment>-<pod-template-hash>-<suffix>,
// a StatefulSet's <statefulset>-<ordinal>, a DaemonSet's <daemonset>-<suffix>.
func ownerFromLabels(pod string, labels map[string]string) string {
	if hash := labels["pod-template-hash"]; hash != "" {
		if i := strings.LastIndex(pod, "-"+hash+"-"); i > 0 {
			return "Deployment/" + pod[:i]
		}
		return ""
	}
	if labels["statefulset.kubernetes.io/pod-name"] == pod {
		if i := strings.LastIndex(pod, "-"); i > 0 {
			return "StatefulSet/" + pod[:i]
		}
	}
	if labels["pod-template-generation"] != "" && labels["controller-revision-hash"] != "" {
		if i := strings.LastIndex(pod, "-"); i > 0 {
			return "DaemonSet/" + pod[:i]
		}
	}
	return ""
}

func (m *MetricsSampler) run() {
	m.Sample(time.Now())
	t := time.NewTicker(sampleInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.Sample(now)
		}
	}
}

func (m *MetricsSampler) close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
}

// Sample takes one sample now (the sampler loop does this every 30 s).
func (m *MetricsSampler) Sample(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pods, err := m.fetch(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.available, m.reason = false, unavailableReason(err)
		return
	}
	t := now.Unix()
	latest := map[string]map[string]PodUsage{}
	for _, p := range pods {
		if latest[p.Namespace] == nil {
			latest[p.Namespace] = map[string]PodUsage{}
		}
		latest[p.Namespace][p.Name] = p
		key := p.Namespace + "/" + p.Name
		s := m.series[key]
		if s == nil {
			s = &series{owner: p.Owner}
			m.series[key] = s
		}
		s.add(t, p.Usage)
	}
	for key, s := range m.series {
		if t-s.lastSeen > int64(historyWindow/time.Second) {
			delete(m.series, key)
		}
	}
	m.latest, m.updatedAt, m.available, m.reason = latest, now, true, ""
}

func unavailableReason(err error) string {
	switch {
	case apierrors.IsNotFound(err), apierrors.IsServiceUnavailable(err):
		return "metrics_server_missing"
	case apierrors.IsForbidden(err):
		return "forbidden"
	default:
		return "error"
	}
}

// Snapshot is the latest usage of a namespace's pods.
type Snapshot struct {
	Available bool       `json:"available"`
	Reason    string     `json:"reason,omitempty"` // metrics_server_missing | forbidden | error | warming_up
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Items     []PodUsage `json:"items"`
}

func (m *MetricsSampler) Namespace(ns string) Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snap := Snapshot{Available: m.available, Reason: m.reason, Items: []PodUsage{}}
	if m.updatedAt.IsZero() {
		if m.reason == "" {
			snap.Reason = "warming_up"
		}
		return snap
	}
	at := m.updatedAt
	snap.UpdatedAt = &at
	for _, p := range m.latest[ns] {
		snap.Items = append(snap.Items, p)
	}
	sort.Slice(snap.Items, func(i, j int) bool { return snap.Items[i].Name < snap.Items[j].Name })
	return snap
}

// PodHistory returns a pod's samples over the last rng (at most 24 h).
func (m *MetricsSampler) PodHistory(ns, pod string, rng time.Duration, now time.Time) []Point {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.series[ns+"/"+pod]
	if s == nil {
		return []Point{}
	}
	return s.points(now.Add(-rng).Unix())
}

// OwnerHistory sums the samples of a workload's pods ("Deployment/web"; all of
// them seen in the window, including replaced ones) per timestamp.
func (m *MetricsSampler) OwnerHistory(ns, owner string, rng time.Duration, now time.Time) []Point {
	m.mu.RLock()
	defer m.mu.RUnlock()
	from := now.Add(-rng).Unix()
	sum := map[int64]Usage{}
	for key, s := range m.series {
		if s.owner != owner || !strings.HasPrefix(key, ns+"/") {
			continue
		}
		for _, p := range s.points(from) {
			u := sum[p.T]
			u.CPU += p.CPU
			u.Mem += p.Mem
			sum[p.T] = u
		}
	}
	out := make([]Point, 0, len(sum))
	for t, u := range sum {
		out = append(out, Point{T: t, Usage: u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}
