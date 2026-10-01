package kube

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ResourceClient struct {
	manager *Manager
}

func NewResourceClient(manager *Manager) *ResourceClient {
	return &ResourceClient{manager: manager}
}

func (c *ResourceClient) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) ListPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListDeployments(ctx context.Context, namespace string) ([]appsv1.Deployment, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListServices(ctx context.Context, namespace string) ([]corev1.Service, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetService(ctx context.Context, namespace, name string) (*corev1.Service, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListConfigMaps(ctx context.Context, namespace string) ([]corev1.ConfigMap, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListIngresses(ctx context.Context, namespace string) ([]networkingv1.Ingress, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetIngress(ctx context.Context, namespace, name string) (*networkingv1.Ingress, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.NetworkingV1().Ingresses(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListCronJobs(ctx context.Context, namespace string) ([]batchv1.CronJob, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetCronJob(ctx context.Context, namespace, name string) (*batchv1.CronJob, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.BatchV1().CronJobs(namespace).Get(ctx, name, metav1.GetOptions{})
}

// RestartDeployment triggers a rolling restart by patching the pod template
// annotation (kubectl.kubernetes.io/restartedAt). Returns the restart timestamp
// applied so callers can echo it in audit entries.
func (c *ResourceClient) RestartDeployment(ctx context.Context, namespace, name string) (string, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return "", fmt.Errorf("kubernetes client not ready")
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		stamp,
	)
	_, err := client.AppsV1().Deployments(namespace).Patch(
		ctx,
		name,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return "", err
	}
	return stamp, nil
}

// ScaleDeployment updates the replicas of a Deployment via its Scale
// subresource. Returns the previous replica count so audit entries can log
// both before and after values.
func (c *ResourceClient) ScaleDeployment(ctx context.Context, namespace, name string, replicas int32) (int32, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return 0, fmt.Errorf("kubernetes client not ready")
	}
	current, err := client.AppsV1().Deployments(namespace).GetScale(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}
	previous := current.Spec.Replicas
	updated := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{
			Name:            current.Name,
			Namespace:       current.Namespace,
			ResourceVersion: current.ResourceVersion,
		},
		Spec: autoscalingv1.ScaleSpec{Replicas: replicas},
	}
	if _, err := client.AppsV1().Deployments(namespace).UpdateScale(ctx, name, updated, metav1.UpdateOptions{}); err != nil {
		return previous, err
	}
	return previous, nil
}
