package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s-dashboard/backend/internal/kube"
)

func res(cpu, mem string) corev1.ResourceRequirements {
	l := corev1.ResourceList{}
	if cpu != "" {
		l[corev1.ResourceCPU] = resource.MustParse(cpu)
	}
	if mem != "" {
		l[corev1.ResourceMemory] = resource.MustParse(mem)
	}
	return corev1.ResourceRequirements{Requests: l, Limits: l}
}

func TestPodResourceSums(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	for _, tc := range []struct {
		name string
		spec corev1.PodSpec
		cpu  int64
	}{
		{"containers summed", corev1.PodSpec{Containers: []corev1.Container{{Resources: res("100m", "")}, {Resources: res("200m", "")}}}, 300},
		{"a bigger init container wins", corev1.PodSpec{
			InitContainers: []corev1.Container{{Resources: res("500m", "")}},
			Containers:     []corev1.Container{{Resources: res("100m", "")}},
		}, 500},
		{"a sidecar runs next to the containers and later init containers", corev1.PodSpec{
			InitContainers: []corev1.Container{{Resources: res("50m", ""), RestartPolicy: &always}, {Resources: res("400m", "")}},
			Containers:     []corev1.Container{{Resources: res("100m", "")}},
		}, 450},
		{"overhead", corev1.PodSpec{Containers: []corev1.Container{{Resources: res("100m", "")}},
			Overhead: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")}}, 110},
	} {
		got := podResourceSums(&corev1.Pod{Spec: tc.spec})
		if got.CPURequests != tc.cpu || got.CPULimits != tc.cpu {
			t.Errorf("%s: %+v, want %d", tc.name, got, tc.cpu)
		}
	}
	// No limit anywhere: 0, the overhead doesn't make one up.
	noLimit := podResourceSums(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{}},
		Overhead: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Mi")}}})
	if noLimit.MemLimits != 0 || noLimit.MemRequests != 1<<20 {
		t.Fatalf("no limit: %+v", noLimit)
	}
}

func TestNodes(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	ctx := context.Background()
	for _, n := range []*corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "", "zone": "a"}},
			Spec: corev1.NodeSpec{Unschedulable: true},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi"), corev1.ResourcePods: resource.MustParse("110")},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				NodeInfo:    corev1.NodeSystemInfo{KubeletVersion: "v1.29.2", OperatingSystem: "linux", Architecture: "arm64"},
				Images:      []corev1.ContainerImage{{Names: []string{"big/image"}}},
			}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n2"}},
	} {
		if _, err := e.client.CoreV1().Nodes().Create(ctx, n, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"}, Spec: corev1.PodSpec{NodeName: "n1",
			Containers: []corev1.Container{{Name: "app", Resources: res("250m", "256Mi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "team-b"}, Spec: corev1.PodSpec{NodeName: "n1",
			Containers: []corev1.Container{{Name: "x", Resources: res("1", "1Gi")}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "team-a"}, Spec: corev1.PodSpec{NodeName: "n2",
			Containers: []corev1.Container{{Name: "app", Resources: res("100m", "")}}}},
	} {
		if _, err := e.client.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ev := range []*corev1.Event{
		{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "n1"},
			Type: "Normal", Reason: "NodeReady", LastTimestamp: metav1.Now()},
		{ObjectMeta: metav1.ObjectMeta{Name: "e2", Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "n1"},
			Type: "Warning", Reason: "Rebooted", LastTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))},
		{ObjectMeta: metav1.ObjectMeta{Name: "e3", Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "n2"}, Type: "Warning"},
	} {
		if _, err := e.client.CoreV1().Events(ev.Namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	fetchNodeUsage = func(context.Context, kubernetes.Interface) (map[string]kube.Usage, error) {
		return map[string]kube.Usage{"n1": {CPU: 900, Mem: 1 << 30}}, nil
	}
	sampler := kube.NewMetricsSampler(func(context.Context) ([]kube.PodUsage, error) {
		return []kube.PodUsage{{Namespace: "team-a", Name: "web", Usage: kube.Usage{CPU: 120, Mem: 100 << 20}}}, nil
	})
	sampler.Sample(time.Now())
	e.alpha.UseMetrics(sampler)

	var list nodesResponse
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/nodes", admin, nil, http.StatusOK)), &list)
	e.waitAudit("node.list.success", "*")
	if len(list.Nodes) != 2 || list.Note != "" || list.MetricsNote != "" {
		t.Fatalf("list %+v", list)
	}
	n1 := list.Nodes[0]
	// The finished pod reserves nothing.
	if n1.Name != "n1" || n1.Pods != 1 || n1.CPURequests != 250 || n1.MemLimits != 256<<20 || n1.PodCapacity != 110 ||
		*n1.CPU != 900 || !n1.Ready || !n1.Unschedulable || len(n1.Roles) != 1 || n1.Roles[0] != "control-plane" ||
		n1.Kubelet != "v1.29.2" || n1.Arch != "arm64" || n1.Labels["zone"] != "a" {
		t.Fatalf("n1 %+v", n1)
	}
	if list.Nodes[1].CPU != nil || list.Nodes[1].Pods != 1 {
		t.Fatalf("n2 %+v", list.Nodes[1])
	}

	var d nodeDetail
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/nodes/n1", admin, nil, http.StatusOK)), &d)
	e.waitAudit("node.get.success", "n1")
	if d.Summary.CPURequests != 250 || len(d.Node.Status.Images) != 0 || d.Node.Status.NodeInfo.Architecture != "arm64" {
		t.Fatalf("detail summary %+v node %+v", d.Summary, d.Node.Status)
	}
	// Every pod on the node, finished ones too; usage where sampled.
	if len(d.Pods) != 2 || d.Pods[0].Name != "web" || d.Pods[0].Usage == nil || d.Pods[0].Usage.CPU != 120 || d.Pods[0].CPURequests != 250 || d.Pods[1].Usage != nil {
		t.Fatalf("pods %+v", d.Pods)
	}
	if len(d.Events) != 2 || d.Events[0].Reason != "Rebooted" {
		t.Fatalf("events (warnings first) %+v", d.Events)
	}

	// No Prometheus: the sampler's node series (empty without the informer's pod → node map).
	var hist historyResponse
	_ = json.Unmarshal([]byte(e.expect("GET", "/api/admin/nodes/n1/metrics/history?range=6h", admin, nil, http.StatusOK)), &hist)
	if hist.Source != "memory" {
		t.Fatalf("history %+v", hist)
	}
}
