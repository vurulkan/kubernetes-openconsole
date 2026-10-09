package kube

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func TestEditableSecretYAML(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "db", Namespace: "team-a", ResourceVersion: "42",
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"password": []byte("hunter2"),
			"config":   []byte("line1\nline2\n"),
			"keystore": {0xff, 0x00, 0x01},
		},
	}
	out, err := EditableSecretYAML(sec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"kind: Secret", "apiVersion: v1", "resourceVersion: \"42\"", "password: hunter2", "config: |", "keystore: /wAB"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "managedFields") {
		t.Errorf("managedFields not stripped:\n%s", text)
	}

	var parsed struct {
		Data       map[string]string `json:"data"`
		StringData map[string]string `json:"stringData"`
	}
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.StringData["password"] != "hunter2" || parsed.StringData["config"] != "line1\nline2\n" {
		t.Errorf("stringData = %#v", parsed.StringData)
	}
	if len(parsed.Data) != 1 || parsed.Data["keystore"] != "/wAB" {
		t.Errorf("binary values must stay base64 in data, got %#v", parsed.Data)
	}
}
