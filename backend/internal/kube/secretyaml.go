package kube

import (
	"encoding/base64"
	"fmt"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// Secrets are edited in a readable form: every UTF-8 value moves from the
// base64 `data` map to plain-text `stringData`; binary values stay in `data`
// as base64. On write the API server merges stringData back into data, and
// because an Update replaces the whole object, a key removed from both maps
// is deleted. The dry-run / apply response goes through the same transform
// so both sides of the diff use the same shape.

// EditableSecretYAML renders a Secret for the YAML editor.
func EditableSecretYAML(sec *corev1.Secret) ([]byte, error) {
	cp := sec.DeepCopy()
	cp.TypeMeta.Kind = "Secret"
	cp.TypeMeta.APIVersion = "v1"
	cp.ManagedFields = nil
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cp)
	if err != nil {
		return nil, fmt.Errorf("convert secret: %w", err)
	}
	return editableSecretFromMap(obj)
}

// editableSecretFromMap applies the data → stringData move to an
// unstructured Secret (as returned by the dynamic client) and renders YAML.
func editableSecretFromMap(obj map[string]interface{}) ([]byte, error) {
	data, _ := obj["data"].(map[string]interface{})
	stringData, _ := obj["stringData"].(map[string]interface{})
	if stringData == nil {
		stringData = map[string]interface{}{}
	}
	for k, v := range data {
		enc, ok := v.(string)
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil || !utf8.Valid(raw) {
			continue // keep binary / odd values as base64 in data
		}
		stringData[k] = string(raw)
		delete(data, k)
	}
	if len(data) == 0 {
		delete(obj, "data")
	}
	if len(stringData) > 0 {
		obj["stringData"] = stringData
	}
	out, err := yaml.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("render secret yaml: %w", err)
	}
	return PrettifyYAML(out), nil
}
