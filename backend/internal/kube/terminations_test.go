package kube

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var yes = true

func crashedPod(restarts int32, exit int32, reason string, at time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-7d4f-abcde", Namespace: "shop", Labels: map[string]string{"pod-template-hash": "7d4f"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-7d4f", Controller: &yes}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", RestartCount: restarts, LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: exit, Reason: reason, FinishedAt: metav1.NewTime(at)},
				}},
				{Name: "sidecar", RestartCount: 0},
			},
		},
	}
}

func TestPodTerminations(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	old := crashedPod(2, 1, "Error", at)
	cur := crashedPod(3, 137, "OOMKilled", at.Add(time.Minute))

	got := podTerminations(old, cur)
	if len(got) != 1 || got[0].Container != "app" || got[0].ExitCode != 137 || got[0].Reason != "OOMKilled" ||
		got[0].Owner != "Deployment/web" || !got[0].LastAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("restart = %+v", got)
	}
	if got := podTerminations(cur, cur); len(got) != 0 {
		t.Fatalf("no new restart (resync) = %+v", got)
	}
	// First sight of a pod: its last termination, which the store dedupes.
	if got := podTerminations(nil, cur); len(got) != 1 {
		t.Fatalf("first sight = %+v", got)
	}
	cur.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: &yes}}
	if got := ownerOfPod(cur); got != "StatefulSet/db" {
		t.Fatalf("statefulset owner = %q", got)
	}
}
