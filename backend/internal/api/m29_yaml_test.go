package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Every YAML view (secrets have their own) answers the same shape — apiVersion
// and kind set, managed fields gone — and records the read (M29: only three did).
func TestYAMLViews(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	meta := metav1.ObjectMeta{Name: "web", Namespace: "team-a", Labels: map[string]string{"app": "web"},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}}
	for _, o := range []runtime.Object{
		&corev1.Pod{ObjectMeta: meta}, &appsv1.Deployment{ObjectMeta: meta}, &corev1.Service{ObjectMeta: meta},
		&corev1.ConfigMap{ObjectMeta: meta, Data: map[string]string{"k": "v"}}, &batchv1.CronJob{ObjectMeta: meta},
		&batchv1.Job{ObjectMeta: meta}, &networkingv1.Ingress{ObjectMeta: meta}, &appsv1.DaemonSet{ObjectMeta: meta},
		&appsv1.StatefulSet{ObjectMeta: meta}, &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: meta},
	} {
		if err := e.client.Tracker().Add(o); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct{ path, apiVersion, kind, audit string }{
		{"pods", "v1", "Pod", "pod.get"},
		{"deployments", "apps/v1", "Deployment", "deployment.get"},
		{"services", "v1", "Service", "service.get"},
		{"configmaps", "v1", "ConfigMap", "configmap.get"},
		{"cronjobs", "batch/v1", "CronJob", "cronjob.get"},
		{"jobs", "batch/v1", "Job", "job.get"},
		{"ingresses", "networking.k8s.io/v1", "Ingress", "ingress.get"},
		{"daemonsets", "apps/v1", "DaemonSet", "daemonset.get"},
		{"statefulsets", "apps/v1", "StatefulSet", "statefulset.get"},
		{"hpas", "autoscaling/v2", "HorizontalPodAutoscaler", "hpa.get"},
	}
	dump := map[string]string{}
	for _, c := range cases {
		var out struct{ YAML string }
		_ = json.Unmarshal([]byte(e.expect("GET", "/api/namespaces/team-a/"+c.path+"/web/yaml", admin, nil, 200)), &out)
		dump[c.path] = out.YAML
		if !strings.Contains(out.YAML, "apiVersion: "+c.apiVersion+"\n") || !strings.Contains(out.YAML, "kind: "+c.kind+"\n") ||
			strings.Contains(out.YAML, "managedFields") || !strings.Contains(out.YAML, "app: web") {
			t.Errorf("%s yaml:\n%s", c.path, out.YAML)
		}
		if os.Getenv("M29_YAML_DUMP") == "" {
			e.waitAudit(c.audit, "web")
		}
	}
	if f := os.Getenv("M29_YAML_DUMP"); f != "" {
		b, _ := json.MarshalIndent(dump, "", " ")
		_ = os.WriteFile(f, b, 0o600)
	}
}
