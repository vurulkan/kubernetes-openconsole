package api

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
)

// Admin → Overview: one answer with everything the screen draws for the caller's cluster,
// cached 15 s per cluster so several admins (and the page's own refresh) don't each walk
// 700 pods and ask the API server again.

const overviewTTL = 15 * time.Second

type overviewUsage struct {
	CPU            int64 `json:"cpu"`
	Mem            int64 `json:"memory"`
	CPUAllocatable int64 `json:"cpuAllocatable"`
	MemAllocatable int64 `json:"memoryAllocatable"`
}

type overviewRestarts struct {
	Namespace string `json:"namespace"`
	Owner     string `json:"owner"` // "Deployment/web", or "Pod/<name>" for a bare pod
	Restarts  int    `json:"restarts"`
	ExitCode  int    `json:"exitCode"` // the most frequent one
	Reason    string `json:"reason,omitempty"`
	Share     int    `json:"share"` // restarts with that exit code
}

type overviewNamespace struct {
	Name      string `json:"name"`
	CPU       int64  `json:"cpu"`
	Mem       int64  `json:"memory"`
	Pods      int    `json:"pods"`
	NearLimit int    `json:"nearLimit"` // pods with a container at >= 90 % of its CPU or memory limit
}

type overviewWarning struct {
	Namespace string    `json:"namespace"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	At        time.Time `json:"at"`
	Count     int32     `json:"count"`
}

type overviewNode struct {
	Name           string   `json:"name"`
	Ready          bool     `json:"ready"`
	Unschedulable  bool     `json:"unschedulable,omitempty"`
	Pressure       []string `json:"pressure"` // MemoryPressure, DiskPressure, PIDPressure
	CPU            *int64   `json:"cpu,omitempty"`
	Mem            *int64   `json:"memory,omitempty"`
	CPUAllocatable int64    `json:"cpuAllocatable"`
	MemAllocatable int64    `json:"memoryAllocatable"`
}

type overviewResponse struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Cluster     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Nodes   int    `json:"nodes"`
	} `json:"cluster"`
	// Current usage, from metrics-server: memory | none; MetricsNote says why (metrics_server_missing …).
	// The 24 h history comes separately (handleOverviewHistory), as Prometheus can take seconds.
	MetricsSource string `json:"metricsSource"`
	MetricsNote   string `json:"metricsNote,omitempty"`

	Pods struct {
		Running int `json:"running"`
		Total   int `json:"total"`
	} `json:"pods"`
	Deployments struct {
		Ready int `json:"ready"`
		Total int `json:"total"`
	} `json:"deployments"`
	// Pods the UI may show red or amber, trimmed; the UI classifies them with utils/podStatus.ts.
	Attention      []corev1.Pod      `json:"attention"`
	AttentionTotal int               `json:"attentionTotal"`
	Counts         []kube.CountPoint `json:"counts"`

	Usage *overviewUsage `json:"usage"`

	Restarts24h    int                `json:"restarts24h"`
	RestartsHourly []int              `json:"restartsHourly"` // 24 buckets, oldest first
	HourStart      int64              `json:"hourStart"`      // unix start of the first bucket
	TopRestarts    []overviewRestarts `json:"topRestarts"`

	Namespaces    []overviewNamespace `json:"namespaces"`
	Warnings      []overviewWarning   `json:"warnings"`
	WarningsTotal int                 `json:"warningsTotal"`
	Nodes         []overviewNode      `json:"nodes"`
	NodesNote     string              `json:"nodesNote,omitempty"` // forbidden | error
}

type overviewEntry struct {
	at   time.Time
	resp *overviewResponse
}

// fetchNodeUsage is metrics.k8s.io in production; tests swap it (the fake clientset has no REST client).
var fetchNodeUsage = kube.NodeUsage

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ci := clusterFrom(r.Context())
	event := models.AuditLog{Verb: audit.VerbViewOverview, ResourceType: audit.KindCluster, ResourceName: ci.Name, Cluster: ci.Name, ClusterID: ci.ID}
	if !user.IsAdmin || user.MustChangePassword {
		event.Outcome, event.Reason = audit.Denied, reasonAdminOnly
		s.auditEvent(r, event)
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	client, ok := kubeFor(r).Client()
	if !ok || !kubeFor(r).Ready() {
		event.Outcome, event.Reason = audit.Failed, "not_connected"
		s.auditEvent(r, event)
		writeError(w, http.StatusServiceUnavailable, "no cluster connected")
		return
	}
	if e, ok := s.overview.Load(ci.ID); ok && time.Since(e.(overviewEntry).at) < overviewTTL {
		s.auditEvent(r, event)
		writeJSON(w, http.StatusOK, e.(overviewEntry).resp)
		return
	}
	resp, err := s.buildOverview(r, client, ci.Name, time.Now())
	if err != nil {
		event.Outcome, event.Reason = audit.Failed, "kubernetes_error"
		event.Details = audit.D{"error": err.Error()}
		s.auditEvent(r, event)
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.overview.Store(ci.ID, overviewEntry{at: time.Now(), resp: resp})
	s.auditEvent(r, event)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) buildOverview(r *http.Request, client kubernetes.Interface, clusterName string, now time.Time) (*overviewResponse, error) {
	ctx := r.Context()
	out := &overviewResponse{GeneratedAt: now, MetricsSource: "none"}
	out.Cluster.Name = clusterName
	if v, err := client.Discovery().ServerVersion(); err == nil {
		out.Cluster.Version = v.GitVersion
	}

	pods, err := s.resources.ListPods(ctx, "")
	if err != nil {
		return nil, err
	}
	deploys, err := s.resources.ListDeployments(ctx, "")
	if err != nil {
		return nil, err
	}
	podPtrs := make([]*corev1.Pod, len(pods))
	byKey := make(map[string]*corev1.Pod, len(pods))
	for i := range pods {
		podPtrs[i] = &pods[i]
		byKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}
	deployPtrs := make([]*appsv1.Deployment, len(deploys))
	for i := range deploys {
		deployPtrs[i] = &deploys[i]
	}
	counts := kube.CountsOf(now.Unix(), podPtrs, deployPtrs)
	out.Pods.Running, out.Pods.Total = counts.PodsRunning, counts.Pods
	out.Deployments.Ready, out.Deployments.Total = counts.DeploysReady, counts.Deploys
	out.Attention = attentionPods(podPtrs, 300)
	out.AttentionTotal = counts.PodsAttention
	out.Counts = []kube.CountPoint{}
	if ic := kubeFor(r).Informers(); ic != nil {
		out.Counts = ic.CountHistory()
	}

	nodes, nodesNote := overviewNodes(ctx, kubeFor(r), client)
	out.Nodes, out.NodesNote = nodes, nodesNote
	out.Cluster.Nodes = len(nodes)
	var alloc overviewUsage
	for _, n := range nodes {
		alloc.CPUAllocatable += n.CPUAllocatable
		alloc.MemAllocatable += n.MemAllocatable
	}

	out.Namespaces = []overviewNamespace{}
	if m := kubeFor(r).Metrics(); m != nil {
		snap := m.All()
		if snap.Available {
			out.MetricsSource = "memory"
			u := alloc
			for _, p := range snap.Items {
				u.CPU += p.CPU
				u.Mem += p.Mem
			}
			out.Usage = &u
			out.Namespaces = namespaceUsage(snap.Items, byKey)
		} else {
			out.MetricsNote = snap.Reason
		}
	}

	rows, err := s.store.ClusterTerminations(ctx, clusterIDFrom(ctx), now.Add(-25*time.Hour))
	if err != nil {
		return nil, err
	}
	out.HourStart, out.RestartsHourly, out.Restarts24h, out.TopRestarts = restartSummary(rows, now)

	warnings, err := warningEvents(ctx, kubeFor(r), client, now.Add(-15*time.Minute))
	if err != nil {
		slog.Warn("overview: warning events", slog.Any("error", err))
	}
	out.WarningsTotal = len(warnings)
	out.Warnings = []overviewWarning{}
	for _, e := range warnings {
		if len(out.Warnings) == 8 {
			break
		}
		out.Warnings = append(out.Warnings, overviewWarning{
			Namespace: e.Namespace, Kind: e.InvolvedObject.Kind, Name: e.InvolvedObject.Name,
			Reason: e.Reason, Message: e.Message, At: kube.EventTime(&e), Count: e.Count,
		})
	}
	return out, nil
}

// A cluster-wide 24 h Prometheus range takes seconds (4–8 s on a 700-pod cluster); its step is
// 5 minutes, so an answer stays fresh that long. In-memory samples are cheap: not cached.
const overviewHistoryTTL = 5 * time.Minute

type historyEntry struct {
	at   time.Time
	resp historyResponse
}

// handleOverviewHistory is the overview's 24 h cluster CPU / memory, apart from the overview
// so the page shows without waiting for Prometheus. Part of the page view: not audited again.
func (s *Server) handleOverviewHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ci := clusterFrom(r.Context())
	if !user.IsAdmin || user.MustChangePassword {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbViewOverview, ResourceType: audit.KindCluster, ResourceName: ci.Name,
			Cluster: ci.Name, ClusterID: ci.ID, Outcome: audit.Denied, Reason: reasonAdminOnly})
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	c := s.promFor(r)
	if v, ok := s.overviewHistory.Load(ci.ID); ok && c != nil {
		e := v.(historyEntry)
		// Stale: answer at once and refresh behind it, one refresh per cluster at a time,
		// so only the first view after a start waits for Prometheus.
		if time.Since(e.at) >= overviewHistoryTTL {
			if _, busy := s.overviewHistoryBusy.LoadOrStore(ci.ID, true); !busy {
				go func(id int) {
					defer s.overviewHistoryBusy.Delete(id)
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					if pts, err := c.History(ctx, "", ".+", "24h", time.Now()); err == nil {
						s.overviewHistory.Store(id, historyEntry{at: time.Now(), resp: historyResponse{Source: "prometheus", Ranges: []string{"24h"}, Points: pts}})
					}
				}(ci.ID)
			}
		}
		writeJSON(w, http.StatusOK, e.resp)
		return
	}
	now := time.Now()
	resp := historyResponse{Source: "memory", Ranges: []string{"24h"}, Points: []kube.Point{}}
	if c != nil {
		pts, err := c.History(r.Context(), "", ".+", "24h", now)
		if err == nil {
			resp.Source, resp.Points = "prometheus", pts
			s.overviewHistory.Store(ci.ID, historyEntry{at: now, resp: resp})
			writeJSON(w, http.StatusOK, resp)
			return
		}
		slog.Warn("overview: prometheus query failed; using in-memory samples", slog.Any("error", err))
		resp.Note = "prometheus_unreachable"
	}
	if m := kubeFor(r).Metrics(); m != nil {
		resp.Points = m.ClusterHistory(24*time.Hour, now)
	}
	writeJSON(w, http.StatusOK, resp)
}

// trimPod keeps what utils/podStatus.ts and podOwner read.
func trimPod(p *corev1.Pod) corev1.Pod {
	t := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: p.Name, Namespace: p.Namespace, DeletionTimestamp: p.DeletionTimestamp,
		OwnerReferences: p.OwnerReferences, Labels: map[string]string{},
	}, Status: p.Status}
	if h := p.Labels["pod-template-hash"]; h != "" {
		t.Labels["pod-template-hash"] = h
	}
	for _, c := range p.Spec.InitContainers {
		t.Spec.InitContainers = append(t.Spec.InitContainers, corev1.Container{Name: c.Name})
	}
	return t
}

// attentionPods trims the pods the UI may flag.
func attentionPods(pods []*corev1.Pod, limit int) []corev1.Pod {
	out := []corev1.Pod{}
	for _, p := range pods {
		if kube.PodNeedsAttention(p) {
			out = append(out, trimPod(p))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func overviewNodes(ctx context.Context, m *kube.Manager, client kubernetes.Interface) ([]overviewNode, string) {
	list, err := listNodes(ctx, m, client)
	if err != nil {
		if apierrors.IsForbidden(err) {
			return []overviewNode{}, "forbidden"
		}
		return []overviewNode{}, "error"
	}
	usage, err := fetchNodeUsage(ctx, client)
	if err != nil {
		usage = nil // the strip still shows readiness and pressure
	}
	out := make([]overviewNode, 0, len(list))
	for _, n := range list {
		out = append(out, nodeState(n, usage))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, ""
}

// namespaceUsage sums the latest pod samples per namespace, busiest CPU first (at most 50).
func namespaceUsage(items []kube.PodUsage, pods map[string]*corev1.Pod) []overviewNamespace {
	byNS := map[string]*overviewNamespace{}
	for _, u := range items {
		ns := byNS[u.Namespace]
		if ns == nil {
			ns = &overviewNamespace{Name: u.Namespace}
			byNS[u.Namespace] = ns
		}
		ns.CPU += u.CPU
		ns.Mem += u.Mem
		ns.Pods++
		if p := pods[u.Namespace+"/"+u.Name]; p != nil && nearLimit(p, u) {
			ns.NearLimit++
		}
	}
	out := make([]overviewNamespace, 0, len(byNS))
	for _, ns := range byNS {
		out = append(out, *ns)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CPU > out[j].CPU || (out[i].CPU == out[j].CPU && out[i].Name < out[j].Name)
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func nearLimit(p *corev1.Pod, u kube.PodUsage) bool {
	for _, c := range p.Spec.Containers {
		used, ok := u.Containers[c.Name]
		if !ok {
			continue
		}
		if l := c.Resources.Limits.Cpu().MilliValue(); l > 0 && float64(used.CPU) >= 0.9*float64(l) {
			return true
		}
		if l := c.Resources.Limits.Memory().Value(); l > 0 && float64(used.Mem) >= 0.9*float64(l) {
			return true
		}
	}
	return false
}

// exitsIn estimates how many of a restart row's exits fell in [from, to). A crash-looping
// container is one row (count exits from first_at to last_at), so its exits are taken as
// evenly spaced over that span.
// shortcut: even spacing ignores CrashLoopBackOff's growing gaps; store each exit if the hourly chart must be exact.
func exitsIn(t models.ContainerTermination, from, to time.Time) int {
	n := t.Count
	if n <= 1 || !t.LastAt.After(t.FirstAt) {
		if !t.LastAt.Before(from) && t.LastAt.Before(to) {
			return n
		}
		return 0
	}
	step := t.LastAt.Sub(t.FirstAt).Seconds() / float64(n-1)
	lo := int(math.Ceil(from.Sub(t.FirstAt).Seconds() / step))
	hi := int(math.Ceil(to.Sub(t.FirstAt).Seconds()/step)) - 1
	lo, hi = max(lo, 0), min(hi, n-1)
	if hi < lo {
		return 0
	}
	return hi - lo + 1
}

// restartSummary buckets the last 24 hours of exits by hour (the current hour last) and ranks
// workloads by restarts, with each one's most frequent exit code.
func restartSummary(rows []models.ContainerTermination, now time.Time) (int64, []int, int, []overviewRestarts) {
	start := now.Truncate(time.Hour).Add(-23 * time.Hour)
	hourly := make([]int, 24)
	total := 0
	type agg struct {
		overviewRestarts
		byCode map[int]int
		reason map[int]string
	}
	byOwner := map[string]*agg{}
	for _, t := range rows {
		n := 0
		for i := range hourly {
			from := start.Add(time.Duration(i) * time.Hour)
			c := exitsIn(t, from, from.Add(time.Hour))
			hourly[i] += c
			n += c
		}
		if n == 0 {
			continue
		}
		total += n
		owner := t.Owner
		if owner == "" {
			owner = "Pod/" + t.Pod
		}
		a := byOwner[t.Namespace+"/"+owner]
		if a == nil {
			a = &agg{overviewRestarts: overviewRestarts{Namespace: t.Namespace, Owner: owner}, byCode: map[int]int{}, reason: map[int]string{}}
			byOwner[t.Namespace+"/"+owner] = a
		}
		a.Restarts += n
		a.byCode[t.ExitCode] += n
		if t.Reason != "" {
			a.reason[t.ExitCode] = t.Reason
		}
	}
	top := make([]overviewRestarts, 0, len(byOwner))
	for _, a := range byOwner {
		for code, n := range a.byCode {
			if n > a.Share || (n == a.Share && code < a.ExitCode) {
				a.ExitCode, a.Share = code, n
			}
		}
		a.Reason = a.reason[a.ExitCode]
		top = append(top, a.overviewRestarts)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Restarts != top[j].Restarts {
			return top[i].Restarts > top[j].Restarts
		}
		return top[i].Namespace+top[i].Owner < top[j].Namespace+top[j].Owner
	})
	if len(top) > 8 {
		top = top[:8]
	}
	return start.Unix(), hourly, total, top
}

// warningEvents: the informer cache when it is warm, else one filtered list call.
func warningEvents(ctx context.Context, m *kube.Manager, client kubernetes.Interface, since time.Time) ([]corev1.Event, error) {
	if ic := m.Informers(); ic != nil && ic.Synced() {
		return ic.WarningEvents(since), nil
	}
	list, err := client.CoreV1().Events("").List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		return nil, err
	}
	out := []corev1.Event{}
	for _, e := range list.Items {
		if !kube.EventTime(&e).Before(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return kube.EventTime(&out[i]).After(kube.EventTime(&out[j])) })
	return out, nil
}
