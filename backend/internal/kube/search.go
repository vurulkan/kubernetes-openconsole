package kube

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// SearchQuery is one ⌘K search: Text matched against names (or IPs when it looks
// like one), narrowed to one Kind (a permission resource name, or "nodes") and to
// namespaces starting with Namespace.
type SearchQuery struct {
	Text      string
	Kind      string
	Namespace string
	Nodes     bool // the caller may see nodes (admins)
	Limit     int
}

// SearchHit is one result row. Pod carries what the UI's kubectl-like status
// needs (utils/podStatus.ts), so the status logic isn't written twice.
type SearchHit struct {
	Kind      string     `json:"kind"`
	Namespace string     `json:"namespace,omitempty"`
	Name      string     `json:"name"`
	IP        string     `json:"ip,omitempty"`
	Status    string     `json:"status,omitempty"`
	Pod       *searchPod `json:"pod,omitempty"`
	rank      int        // 0 = exact / prefix, 1 = substring
	order     int        // kind order
	obj       any        // the pod, summarized only for the hits kept
}

type searchPod struct {
	Metadata struct {
		DeletionTimestamp *metav1.Time `json:"deletionTimestamp,omitempty"`
	} `json:"metadata"`
	Spec struct {
		InitContainers []searchInit `json:"initContainers,omitempty"`
	} `json:"spec"`
	Status corev1.PodStatus `json:"status"`
}

type searchInit struct {
	Name          string                         `json:"name"`
	RestartPolicy *corev1.ContainerRestartPolicy `json:"restartPolicy,omitempty"`
}

// LooksLikeIP: digits and dots with at least one dot ("10.42.", "10.42.0.7"); a
// bare number is a name search, so "10" doesn't bring every pod.
func LooksLikeIP(q string) bool {
	return strings.Contains(q, ".") && strings.Trim(q, "0123456789.") == ""
}

// searchKinds in result order; IP searches only reach pods, services and nodes.
var searchKinds = []string{"pods", "deployments", "statefulsets", "daemonsets", "services", "ingresses",
	"configmaps", "jobs", "cronjobs", "hpas", "nodes"}

var informerKind = map[string]string{"pods": "Pod", "deployments": "Deployment", "statefulsets": "StatefulSet",
	"daemonsets": "DaemonSet", "services": "Service", "ingresses": "Ingress", "configmaps": "ConfigMap",
	"jobs": "Job", "cronjobs": "CronJob", "hpas": "HorizontalPodAutoscaler", "nodes": "Node"}

// Search lists matching objects from the informer cache only: a kind whose lister
// isn't usable is skipped, never read from the API server. allow(namespace, resource)
// decides what the caller may list; it is asked once per pair.
// shortcut: a linear scan of every cached object per search (10k pods ≈ a few ms, see
// BenchmarkSearch); add a name / IP index if large clusters show it.
func (c *InformerCache) Search(q SearchQuery, allow func(namespace, resource string) bool) []SearchHit {
	text := strings.ToLower(strings.TrimSpace(q.Text))
	ipMode := LooksLikeIP(text)
	memo := map[[2]string]bool{}
	allowed := func(ns, res string) bool {
		k := [2]string{ns, res}
		v, ok := memo[k]
		if !ok {
			v = allow(ns, res)
			memo[k] = v
		}
		return v
	}
	var hits []SearchHit
	add := func(h SearchHit, order int, values ...string) {
		if q.Namespace != "" && !strings.HasPrefix(h.Namespace, q.Namespace) { // nodes have none: out too
			return
		}
		rank := -1
		if text == "" {
			rank = 0
		}
		for _, v := range values {
			v = strings.ToLower(v)
			switch {
			case v == "":
			case v == text || (!ipMode && strings.HasPrefix(v, text)):
				rank = 0
			case strings.HasPrefix(v, text) || (!ipMode && strings.Contains(v, text)):
				if rank < 0 {
					rank = 1
				}
			}
			if rank == 0 {
				break
			}
		}
		if rank < 0 || (h.Kind != "nodes" && !allowed(h.Namespace, h.Kind)) {
			return
		}
		if ipMode {
			h.IP = firstWithPrefix(values, text)
		}
		h.rank, h.order = rank, order
		hits = append(hits, h)
	}
	for order, kind := range searchKinds {
		if (q.Kind != "" && q.Kind != kind) || (kind == "nodes" && !q.Nodes) ||
			(ipMode && kind != "pods" && kind != "services" && kind != "nodes") || !c.Usable(informerKind[kind]) {
			continue
		}
		if ipMode && kind == "nodes" {
			order = -1 // a hostNetwork pod shares its node's IP: the node first
		}
		c.searchKind(kind, order, ipMode, add)
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.order != b.order {
			return a.order < b.order
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	if q.Limit > 0 && len(hits) > q.Limit {
		hits = hits[:q.Limit]
	}
	for i := range hits {
		if hits[i].Kind == "pods" {
			hits[i].Pod = podSummary(hits[i].obj.(*corev1.Pod))
		}
		hits[i].obj = nil
	}
	return hits
}

func (c *InformerCache) searchKind(kind string, order int, ipMode bool, add func(SearchHit, int, ...string)) {
	all := labels.Everything()
	hit := func(o metav1.Object, status string) SearchHit {
		return SearchHit{Kind: kind, Namespace: o.GetNamespace(), Name: o.GetName(), Status: status}
	}
	switch kind {
	case "pods":
		objs, _ := c.podLister.List(all)
		for _, o := range objs {
			h := hit(o, "")
			h.obj = o
			if ipMode {
				ips := make([]string, 0, len(o.Status.PodIPs)+1)
				ips = append(ips, o.Status.PodIP)
				for _, ip := range o.Status.PodIPs {
					ips = append(ips, ip.IP)
				}
				add(h, order, ips...)
			} else {
				add(h, order, o.Name)
			}
		}
	case "services":
		objs, _ := c.serviceLister.List(all)
		for _, o := range objs {
			h := hit(o, string(o.Spec.Type))
			if ipMode {
				ips := append([]string{o.Spec.ClusterIP}, o.Spec.ClusterIPs...)
				ips = append(ips, o.Spec.ExternalIPs...)
				for _, in := range o.Status.LoadBalancer.Ingress {
					ips = append(ips, in.IP)
				}
				add(h, order, ips...)
			} else {
				add(h, order, o.Name)
			}
		}
	case "nodes":
		if c.nodeLister == nil {
			return
		}
		objs, _ := c.nodeLister.List(all)
		for _, o := range objs {
			h := hit(o, nodeReady(o))
			if ipMode {
				var ips []string
				for _, a := range o.Status.Addresses {
					if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
						ips = append(ips, a.Address)
					}
				}
				add(h, order, ips...)
			} else {
				add(h, order, o.Name)
			}
		}
	case "deployments":
		objs, _ := c.deploymentLister.List(all)
		for _, o := range objs {
			want := int32(1)
			if o.Spec.Replicas != nil {
				want = *o.Spec.Replicas
			}
			add(hit(o, fmt.Sprintf("%d/%d", o.Status.ReadyReplicas, want)), order, o.Name)
		}
	case "statefulsets":
		objs, _ := c.statefulsetLister.List(all)
		for _, o := range objs {
			want := int32(1)
			if o.Spec.Replicas != nil {
				want = *o.Spec.Replicas
			}
			add(hit(o, fmt.Sprintf("%d/%d", o.Status.ReadyReplicas, want)), order, o.Name)
		}
	case "daemonsets":
		objs, _ := c.daemonsetLister.List(all)
		for _, o := range objs {
			add(hit(o, fmt.Sprintf("%d/%d", o.Status.NumberReady, o.Status.DesiredNumberScheduled)), order, o.Name)
		}
	case "ingresses":
		objs, _ := c.ingressLister.List(all)
		for _, o := range objs {
			add(hit(o, ""), order, o.Name)
		}
	case "configmaps":
		objs, _ := c.configmapLister.List(all)
		for _, o := range objs {
			add(hit(o, ""), order, o.Name)
		}
	case "jobs":
		objs, _ := c.jobLister.List(all)
		for _, o := range objs {
			add(hit(o, ""), order, o.Name)
		}
	case "cronjobs":
		objs, _ := c.cronjobLister.List(all)
		for _, o := range objs {
			add(hit(o, o.Spec.Schedule), order, o.Name)
		}
	case "hpas":
		objs, _ := c.hpaLister.List(all)
		for _, o := range objs {
			add(hit(o, ""), order, o.Name)
		}
	}
}

func firstWithPrefix(values []string, prefix string) string {
	for _, v := range values {
		if v != "" && strings.HasPrefix(v, prefix) {
			return v
		}
	}
	return ""
}

func nodeReady(n *corev1.Node) string {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			if c.Status == corev1.ConditionTrue {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Unknown"
}

func podSummary(p *corev1.Pod) *searchPod {
	s := &searchPod{Status: p.Status}
	s.Metadata.DeletionTimestamp = p.DeletionTimestamp
	for _, ic := range p.Spec.InitContainers {
		s.Spec.InitContainers = append(s.Spec.InitContainers, searchInit{Name: ic.Name, RestartPolicy: ic.RestartPolicy})
	}
	return s
}
