package kube

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k8s-dashboard/backend/internal/models"
)

// ownerOfPod names the workload a pod belongs to: "Deployment/web" (through
// its ReplicaSet), "StatefulSet/db", "DaemonSet/agent", "Job/migrate"; "" for a bare pod.
func ownerOfPod(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if hash := p.Labels["pod-template-hash"]; hash != "" && strings.HasSuffix(o.Name, "-"+hash) {
				return "Deployment/" + strings.TrimSuffix(o.Name, "-"+hash)
			}
		}
		return o.Kind + "/" + o.Name
	}
	return ""
}

// podTerminations returns the exits a pod update reveals: for each container
// (init ones too) whose restart count went up, its last termination. A pod
// seen for the first time (old == nil: informer start, OpenConsole restart)
// reports every last termination it still carries; the store drops the ones
// it already has.
func podTerminations(old, cur *corev1.Pod) []models.ContainerTermination {
	before := map[string]int32{}
	if old != nil {
		for _, s := range append(old.Status.InitContainerStatuses, old.Status.ContainerStatuses...) {
			before[s.Name] = s.RestartCount
		}
	}
	var out []models.ContainerTermination
	for _, s := range append(cur.Status.InitContainerStatuses, cur.Status.ContainerStatuses...) {
		t := s.LastTerminationState.Terminated
		if t == nil || (old != nil && s.RestartCount <= before[s.Name]) {
			continue
		}
		out = append(out, models.ContainerTermination{
			Namespace: cur.Namespace,
			Pod:       cur.Name,
			Container: s.Name,
			Owner:     ownerOfPod(cur),
			ExitCode:  int(t.ExitCode),
			Signal:    int(t.Signal),
			Reason:    t.Reason,
			FirstAt:   t.FinishedAt.Time,
			LastAt:    t.FinishedAt.Time,
			Count:     1,
		})
	}
	return out
}
