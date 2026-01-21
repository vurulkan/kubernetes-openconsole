package kube

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
