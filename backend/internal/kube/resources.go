package kube

import (
	"context"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

// The informer indexer is backed by a Go map, so lister results come back in
// an unspecified order. Sort by Name after copying from the lister so the UI
// matches the alphabetical ordering the API server returns, which is what
// users had before the informer rewrite.

type ResourceClient struct {
	manager *Manager
}

func NewResourceClient(manager *Manager) *ResourceClient {
	return &ResourceClient{manager: manager}
}

// cache returns the InformerCache if it exists and the initial sync has
// completed. During the warmup window (or when no cluster is active) the
// callers fall back to a direct API call so the UI doesn't see an empty list.
func (c *ResourceClient) cache() *InformerCache {
	ic := c.manager.Informers()
	if ic == nil || !ic.Synced() {
		return nil
	}
	return ic
}

func (c *ResourceClient) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	if ic := c.cache(); ic != nil {
		objs, err := ic.namespaceLister.List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]corev1.Namespace, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.podLister.Pods(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]corev1.Pod, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.deploymentLister.Deployments(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]appsv1.Deployment, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.serviceLister.Services(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]corev1.Service, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.configmapLister.ConfigMaps(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]corev1.ConfigMap, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.ingressLister.Ingresses(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]networkingv1.Ingress, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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
	if ic := c.cache(); ic != nil {
		objs, err := ic.cronjobLister.CronJobs(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]batchv1.CronJob, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
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

// ListJobs enumerates batchv1 Jobs in a namespace. Shown in its own
// dashboard tab so operators can see short-lived or one-shot work (CronJob
// executions, image-pull helpers, migration pods) without flooding the
// Pods list with throwaway rows.
func (c *ResourceClient) ListJobs(ctx context.Context, namespace string) ([]batchv1.Job, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	if ic := c.cache(); ic != nil {
		objs, err := ic.jobLister.Jobs(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]batchv1.Job, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
	}
	result, err := client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetJob(ctx context.Context, namespace, name string) (*batchv1.Job, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
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

// ListDaemonSets, ListStatefulSets, ListHPAs — same lister-first,
// live-fallback shape as the rest of the resource queries. HPAs come from
// autoscaling/v2 because that is the version the dashboard renders metrics
// for; the (deprecated) v1 object is auto-converted by the API server when
// an operator writes a v2 object.

func (c *ResourceClient) ListDaemonSets(ctx context.Context, namespace string) ([]appsv1.DaemonSet, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	if ic := c.cache(); ic != nil {
		objs, err := ic.daemonsetLister.DaemonSets(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]appsv1.DaemonSet, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
	}
	result, err := client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetDaemonSet(ctx context.Context, namespace, name string) (*appsv1.DaemonSet, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListStatefulSets(ctx context.Context, namespace string) ([]appsv1.StatefulSet, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	if ic := c.cache(); ic != nil {
		objs, err := ic.statefulsetLister.StatefulSets(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]appsv1.StatefulSet, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
	}
	result, err := client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetStatefulSet(ctx context.Context, namespace, name string) (*appsv1.StatefulSet, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *ResourceClient) ListHPAs(ctx context.Context, namespace string) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	if ic := c.cache(); ic != nil {
		objs, err := ic.hpaLister.HorizontalPodAutoscalers(namespace).List(labels.Everything())
		if err == nil {
			sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
			out := make([]autoscalingv2.HorizontalPodAutoscaler, 0, len(objs))
			for _, o := range objs {
				out = append(out, *o)
			}
			return out, nil
		}
	}
	result, err := client.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *ResourceClient) GetHPA(ctx context.Context, namespace, name string) (*autoscalingv2.HorizontalPodAutoscaler, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.AutoscalingV2().HorizontalPodAutoscalers(namespace).Get(ctx, name, metav1.GetOptions{})
}

// ScaleStatefulSet mirrors ScaleDeployment on the Scale subresource. The
// previous replica count is returned so audit entries can log before+after.
func (c *ResourceClient) ScaleStatefulSet(ctx context.Context, namespace, name string, replicas int32) (int32, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return 0, fmt.Errorf("kubernetes client not ready")
	}
	current, err := client.AppsV1().StatefulSets(namespace).GetScale(ctx, name, metav1.GetOptions{})
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
	if _, err := client.AppsV1().StatefulSets(namespace).UpdateScale(ctx, name, updated, metav1.UpdateOptions{}); err != nil {
		return previous, err
	}
	return previous, nil
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

// Secrets deliberately bypass the informer cache: caching would keep every
// secret value in the cluster resident in memory and need list/watch on
// secrets cluster-wide. Reads go straight to the API server instead.

func (c *ResourceClient) ListSecrets(ctx context.Context, namespace string) ([]corev1.Secret, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	result, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	sort.Slice(result.Items, func(i, j int) bool { return result.Items[i].Name < result.Items[j].Name })
	return result.Items, nil
}

func (c *ResourceClient) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	client, ok := c.manager.Client()
	if !ok || !c.manager.Ready() {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	return client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}
