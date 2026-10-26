package api

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/prom"
)

// Nodes screen (admins only, read only): the node list with usage and what is reserved on each
// node, cached 15 s per cluster like the overview; a node's detail from the informer cache.

const nodesTTL = 15 * time.Second

// podSums is what pods reserve: CPU in millicores, memory in bytes.
type podSums struct {
	CPURequests int64 `json:"cpuRequests"`
	CPULimits   int64 `json:"cpuLimits"`
	MemRequests int64 `json:"memoryRequests"`
	MemLimits   int64 `json:"memoryLimits"`
}

func (a *podSums) add(b podSums) {
	a.CPURequests += b.CPURequests
	a.CPULimits += b.CPULimits
	a.MemRequests += b.MemRequests
	a.MemLimits += b.MemLimits
}

type nodeSummary struct {
	overviewNode
	podSums
	Roles       []string          `json:"roles"`
	Kubelet     string            `json:"kubeletVersion"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	Created     time.Time         `json:"created"`
	Labels      map[string]string `json:"labels"`
	Pods        int               `json:"pods"` // not finished (kubectl's "Non-terminated Pods")
	PodCapacity int64             `json:"podCapacity"`
}

type nodesResponse struct {
	GeneratedAt time.Time     `json:"generatedAt"`
	Nodes       []nodeSummary `json:"nodes"`
	Note        string        `json:"note,omitempty"`        // forbidden | error: the token can't list nodes
	MetricsNote string        `json:"metricsNote,omitempty"` // metrics_unavailable: no usage column
}

type nodesEntry struct {
	at   time.Time
	resp *nodesResponse
}

// nodePod is a pod on the node, trimmed to what the drawer shows.
type nodePod struct {
	corev1.Pod
	podSums
	Usage *kube.Usage `json:"usage,omitempty"`
}

type nodeDetail struct {
	Summary nodeSummary    `json:"summary"`
	Node    corev1.Node    `json:"node"` // without managed fields and the image list
	Pods    []nodePod      `json:"pods"`
	Events  []corev1.Event `json:"events"` // Warnings first, then newest
}

// nodeAdmin lets admins through; anyone else gets 403 and a denied audit event.
func (s *Server) nodeAdmin(w http.ResponseWriter, r *http.Request, verb, name string) bool {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	if !user.IsAdmin || user.MustChangePassword {
		s.auditEvent(r, models.AuditLog{Verb: verb, ResourceType: audit.Kind("nodes"), ResourceName: name, Outcome: audit.Denied, Reason: reasonAdminOnly})
		writeError(w, http.StatusForbidden, "admin only")
		return false
	}
	return true
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if !s.nodeAdmin(w, r, audit.VerbList, "*") {
		return
	}
	resp, err := s.nodeList(r)
	if err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbList, ResourceType: audit.Kind("nodes"), ResourceName: "*",
			Outcome: audit.Failed, Reason: failReason(err), Details: failDetails(err, nil)})
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.auditRead(r, audit.VerbList, "nodes", "", "*")
	writeJSON(w, http.StatusOK, resp)
}

// nodeList is the cached list, built again when older than 15 s.
func (s *Server) nodeList(r *http.Request) (*nodesResponse, error) {
	id := clusterIDFrom(r.Context())
	if e, ok := s.nodes.Load(id); ok && time.Since(e.(nodesEntry).at) < nodesTTL {
		return e.(nodesEntry).resp, nil
	}
	client, ok := kubeFor(r).Client()
	if !ok || !kubeFor(r).Ready() {
		return nil, errNotConnected
	}
	resp, err := s.buildNodes(r.Context(), kubeFor(r), client)
	if err != nil {
		return nil, err
	}
	s.nodes.Store(id, nodesEntry{at: resp.GeneratedAt, resp: resp})
	return resp, nil
}

func (s *Server) buildNodes(ctx context.Context, m *kube.Manager, client kubernetes.Interface) (*nodesResponse, error) {
	out := &nodesResponse{GeneratedAt: time.Now(), Nodes: []nodeSummary{}}
	nodes, err := listNodes(ctx, m, client)
	if err != nil {
		out.Note = "error"
		if apierrors.IsForbidden(err) {
			out.Note = "forbidden"
		}
		return out, nil
	}
	pods, err := s.resources.ListPods(ctx, "")
	if err != nil {
		return nil, err
	}
	type onNode struct {
		n    int
		sums podSums
	}
	byNode := map[string]*onNode{}
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" || podFinished(p) {
			continue
		}
		o := byNode[p.Spec.NodeName]
		if o == nil {
			o = &onNode{}
			byNode[p.Spec.NodeName] = o
		}
		o.n++
		o.sums.add(podResourceSums(p))
	}
	usage, err := fetchNodeUsage(ctx, client)
	if err != nil {
		out.MetricsNote = "metrics_unavailable"
	}
	for _, n := range nodes {
		row := nodeSummary{
			overviewNode: nodeState(n, usage),
			Roles:        nodeRoles(n.Labels),
			Kubelet:      n.Status.NodeInfo.KubeletVersion,
			OS:           n.Status.NodeInfo.OperatingSystem,
			Arch:         n.Status.NodeInfo.Architecture,
			Created:      n.CreationTimestamp.Time,
			Labels:       n.Labels,
			PodCapacity:  n.Status.Allocatable.Pods().Value(),
		}
		if o := byNode[n.Name]; o != nil {
			row.Pods, row.podSums = o.n, o.sums
		}
		out.Nodes = append(out.Nodes, row)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Name < out.Nodes[j].Name })
	return out, nil
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !s.nodeAdmin(w, r, audit.VerbGet, name) {
		return
	}
	fail := func(status int, err error) {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbGet, ResourceType: audit.Kind("nodes"), ResourceName: name,
			Outcome: audit.Failed, Reason: failReason(err), Details: failDetails(err, nil)})
		writeError(w, status, err.Error())
	}
	list, err := s.nodeList(r)
	if err != nil {
		fail(http.StatusServiceUnavailable, err)
		return
	}
	client, _ := kubeFor(r).Client()
	nodes, err := listNodes(r.Context(), kubeFor(r), client)
	if err != nil {
		fail(http.StatusServiceUnavailable, err)
		return
	}
	var out nodeDetail
	found := false
	for _, n := range nodes {
		if n.Name == name {
			out.Node, found = *n.DeepCopy(), true
		}
	}
	for _, row := range list.Nodes {
		if row.Name == name {
			out.Summary = row
		}
	}
	if !found {
		fail(http.StatusNotFound, apierrors.NewNotFound(corev1.Resource("nodes"), name))
		return
	}
	// A node just added can be missing from a list up to 15 s old.
	if out.Summary.Name == "" {
		out.Summary = nodeSummary{overviewNode: nodeState(&out.Node, nil), Roles: nodeRoles(out.Node.Labels), Labels: out.Node.Labels}
	}
	out.Node.ManagedFields, out.Node.Status.Images = nil, nil

	pods, err := s.nodePods(r.Context(), kubeFor(r), name)
	if err != nil {
		fail(http.StatusServiceUnavailable, err)
		return
	}
	usage := map[string]kube.Usage{}
	if m := kubeFor(r).Metrics(); m != nil {
		for _, u := range m.All().Items {
			usage[u.Namespace+"/"+u.Name] = u.Usage
		}
	}
	out.Pods = make([]nodePod, 0, len(pods))
	for _, p := range pods {
		np := nodePod{Pod: trimPod(p), podSums: podResourceSums(p)}
		if u, ok := usage[p.Namespace+"/"+p.Name]; ok {
			np.Usage = &u
		}
		out.Pods = append(out.Pods, np)
	}
	sort.Slice(out.Pods, func(i, j int) bool {
		a, b := out.Pods[i], out.Pods[j]
		return a.Namespace < b.Namespace || (a.Namespace == b.Namespace && a.Name < b.Name)
	})

	out.Events, err = nodeEvents(r.Context(), kubeFor(r), client, name)
	if err != nil {
		slog.Warn("node events", slog.String("node", name), slog.Any("error", err))
		out.Events = []corev1.Event{}
	}
	s.auditRead(r, audit.VerbGet, "nodes", "", name)
	writeJSON(w, http.StatusOK, out)
}

type nodeHistoryKey struct {
	cluster   int
	node, rng string
}

// handleNodeHistory is a node's CPU / memory over ?range=, apart from the drawer so it opens
// without waiting for Prometheus. Part of the drawer's view: not audited again.
func (s *Server) handleNodeHistory(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !s.nodeAdmin(w, r, audit.VerbGet, name) {
		return
	}
	s.history(w, r,
		func(c *prom.Client, rng string) ([]prom.Point, error) {
			key := nodeHistoryKey{clusterIDFrom(r.Context()), name, rng}
			step := prom.Ranges["1h"].Step
			if rg, ok := prom.Ranges[rng]; ok {
				step = rg.Step
			}
			// A new point comes once a step; a node is asked for again whenever its drawer opens.
			if v, ok := s.nodeHistory.Load(key); ok && time.Since(v.(historyEntry).at) < step {
				return v.(historyEntry).resp.Points.([]prom.Point), nil
			}
			var addrs []string
			client, _ := kubeFor(r).Client()
			if nodes, err := listNodes(r.Context(), kubeFor(r), client); err == nil {
				for _, n := range nodes {
					if n.Name != name {
						continue
					}
					for _, a := range n.Status.Addresses {
						if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
							addrs = append(addrs, a.Address)
						}
					}
				}
			}
			pts, err := c.NodeHistory(r.Context(), name, addrs, rng, time.Now())
			if err == nil && len(pts) == 0 {
				// Neither a node nor an instance label: the pods on the node now, summed.
				pods, perr := s.nodePods(r.Context(), kubeFor(r), name)
				if perr == nil && len(pods) > 0 {
					names := make([]string, len(pods))
					for i, p := range pods {
						names[i] = regexp.QuoteMeta(p.Name)
					}
					pts, err = c.History(r.Context(), "", strings.Join(names, "|"), rng, time.Now())
				}
			}
			if err == nil {
				s.nodeHistory.Store(key, historyEntry{at: time.Now(), resp: historyResponse{Points: pts}})
			}
			return pts, err
		},
		func(m *kube.MetricsSampler, rng time.Duration) []kube.Point {
			return m.NodeHistory(name, rng, time.Now())
		})
}

// dropHistory forgets a cluster's cached Prometheus answers (cluster or its Prometheus changed).
func (s *Server) dropHistory(id int) {
	s.overviewHistory.Delete(id)
	s.nodeHistory.Range(func(k, _ any) bool {
		if k.(nodeHistoryKey).cluster == id {
			s.nodeHistory.Delete(k)
		}
		return true
	})
}

// listNodes reads the informer cache when it watches nodes, else asks the API server.
func listNodes(ctx context.Context, m *kube.Manager, client kubernetes.Interface) ([]*corev1.Node, error) {
	if ic := m.Informers(); ic != nil {
		if nodes, ok := ic.Nodes(); ok {
			return nodes, nil
		}
	}
	list, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]*corev1.Node, len(list.Items))
	for i := range list.Items {
		out[i] = &list.Items[i]
	}
	return out, nil
}

// nodePods: the cache's nodeName index when warm, else every pod filtered.
func (s *Server) nodePods(ctx context.Context, m *kube.Manager, node string) ([]*corev1.Pod, error) {
	if ic := m.Informers(); ic != nil && ic.Synced() {
		return ic.NodePods(node), nil
	}
	pods, err := s.resources.ListPods(ctx, "")
	if err != nil {
		return nil, err
	}
	out := []*corev1.Pod{}
	for i := range pods {
		if pods[i].Spec.NodeName == node {
			out = append(out, &pods[i])
		}
	}
	return out, nil
}

func nodeEvents(ctx context.Context, m *kube.Manager, client kubernetes.Interface, node string) ([]corev1.Event, error) {
	var out []corev1.Event
	if ic := m.Informers(); ic != nil && ic.Synced() {
		out = ic.NodeEvents(node)
	} else {
		list, err := client.CoreV1().Events("").List(ctx, metav1.ListOptions{FieldSelector: "involvedObject.kind=Node,involvedObject.name=" + node})
		if err != nil {
			return nil, err
		}
		for _, e := range list.Items {
			if e.InvolvedObject.Kind == "Node" && e.InvolvedObject.Name == node {
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		wi, wj := out[i].Type == corev1.EventTypeWarning, out[j].Type == corev1.EventTypeWarning
		if wi != wj {
			return wi
		}
		return kube.EventTime(&out[i]).After(kube.EventTime(&out[j]))
	})
	if len(out) > 50 {
		out = out[:50]
	}
	if out == nil {
		out = []corev1.Event{}
	}
	return out, nil
}

// nodeState is a node's readiness, pressure, allocatable and (when known) usage.
func nodeState(n *corev1.Node, usage map[string]kube.Usage) overviewNode {
	node := overviewNode{
		Name: n.Name, Unschedulable: n.Spec.Unschedulable, Pressure: []string{},
		CPUAllocatable: n.Status.Allocatable.Cpu().MilliValue(),
		MemAllocatable: n.Status.Allocatable.Memory().Value(),
	}
	for _, c := range n.Status.Conditions {
		switch {
		case c.Type == corev1.NodeReady:
			node.Ready = c.Status == corev1.ConditionTrue
		case c.Status == corev1.ConditionTrue:
			node.Pressure = append(node.Pressure, string(c.Type))
		}
	}
	if u, ok := usage[n.Name]; ok {
		node.CPU, node.Mem = &u.CPU, &u.Mem
	}
	return node
}

// nodeRoles reads node-role.kubernetes.io/<role> labels (and the older kubernetes.io/role).
func nodeRoles(labels map[string]string) []string {
	out := []string{}
	for k, v := range labels {
		if role, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && role != "" {
			out = append(out, role)
		} else if k == "kubernetes.io/role" && v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func podFinished(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// podResourceSums is what a pod reserves on its node, the way the scheduler counts it:
// its containers summed, or its largest init container if that is more; sidecars
// (init containers with restartPolicy Always) run next to both. Plus the pod overhead.
func podResourceSums(p *corev1.Pod) podSums {
	total := func(limits, cpu bool) int64 {
		get := func(r corev1.ResourceRequirements) int64 {
			l := r.Requests
			if limits {
				l = r.Limits
			}
			if cpu {
				return l.Cpu().MilliValue()
			}
			return l.Memory().Value()
		}
		var sum, sidecars, initMax int64
		for _, c := range p.Spec.Containers {
			sum += get(c.Resources)
		}
		for _, c := range p.Spec.InitContainers {
			v := get(c.Resources)
			if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				sidecars += v
				initMax = max(initMax, sidecars)
				continue
			}
			initMax = max(initMax, sidecars+v)
		}
		out := max(sum+sidecars, initMax)
		if out > 0 || !limits {
			out += get(corev1.ResourceRequirements{Requests: p.Spec.Overhead, Limits: p.Spec.Overhead})
		}
		return out
	}
	return podSums{CPURequests: total(false, true), CPULimits: total(true, true), MemRequests: total(false, false), MemLimits: total(true, false)}
}
