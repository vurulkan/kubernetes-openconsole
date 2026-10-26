package kube

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCountsOf(t *testing.T) {
	ready := corev1.ContainerStatus{Ready: true}
	now := metav1.Now()
	pods := []*corev1.Pod{
		{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{ready}}},
		{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{ready, {}}}},                                                     // one not ready
		{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{ready}}}, // terminating
		{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{Status: corev1.PodStatus{Phase: corev1.PodPending}},
	}
	two, zero := int32(2), int32(0)
	deploys := []*appsv1.Deployment{
		{Spec: appsv1.DeploymentSpec{Replicas: &two}, Status: appsv1.DeploymentStatus{ReadyReplicas: 2}},
		{Spec: appsv1.DeploymentSpec{Replicas: &two}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1}},
		{Spec: appsv1.DeploymentSpec{Replicas: &zero}},
	}
	got := CountsOf(7, pods, deploys)
	want := CountPoint{T: 7, PodsRunning: 3, Pods: 5, PodsAttention: 3, DeploysReady: 2, Deploys: 3}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
