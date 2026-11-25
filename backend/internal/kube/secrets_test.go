package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
)

// Helm releases come from the metadata client (no data downloaded), the rest in full.
func TestListSecretsHelmMetadataOnly(t *testing.T) {
	app := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"k": []byte("v")}}
	client := fake.NewSimpleClientset(app)
	scheme := runtime.NewScheme()
	_ = metav1.AddMetaToScheme(scheme)
	helm := &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "sh.helm.release.v1.web.v1", Namespace: "ns", Labels: map[string]string{"owner": "helm"}}}
	m := NewManagerWithClient(client)
	m.meta = metadatafake.NewSimpleMetadataClient(scheme, helm)
	items, err := NewResourceClient().ListSecrets(WithManager(t.Context(), m), "ns")
	if err != nil || len(items) != 2 {
		t.Fatalf("items = %+v, %v", items, err)
	}
	if items[0].Name != "app" || string(items[0].Data["k"]) != "v" {
		t.Fatalf("app = %+v", items[0])
	}
	if items[1].Type != HelmRelease || items[1].Data != nil || items[1].Labels["owner"] != "helm" {
		t.Fatalf("helm = %+v", items[1])
	}
}
