package kube

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

// ApplyResult carries whatever the API server returned after a (possibly
// dry-run) update. AppliedYAML is the server-canonicalized object re-rendered
// as YAML so the diff view can show "what will actually be stored" vs. "what
// the user typed" — the two differ for defaulted fields.
type ApplyResult struct {
	AppliedYAML string
	// DryRun true means no change was persisted; false means the server
	// accepted and wrote the object.
	DryRun bool
}

// Apply validates and (dry-run or writes) a resource described by a YAML
// payload. Namespace and name from the URL are the source of truth; mismatches
// in the YAML's metadata are treated as a client error so an operator can't
// accidentally rename something or drop metadata and end up renaming on apply.
//
// Optimistic concurrency: the YAML must carry metadata.resourceVersion as it
// came from GET — a stale version makes the API server return 409 Conflict,
// which the UI surfaces as "please re-open and retry".
//
// kind is the Kubernetes Kind for this GVR; the caller carries it alongside
// the GVR so we can inject apiVersion/kind into submitted YAML that is
// missing them (older cached YAML from pre-2.6.1 did not include TypeMeta).
func (c *ResourceClient) Apply(
	ctx context.Context,
	gvr schema.GroupVersionResource,
	kind string,
	namespace, name string,
	raw []byte,
	dryRun bool,
) (*ApplyResult, error) {
	cfg, ok := c.mgr(ctx).RESTConfig()
	if !ok {
		return nil, fmt.Errorf("kubernetes client not ready")
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}

	// YAML → JSON → Unstructured. sigs.k8s.io/yaml handles the YAML→JSON
	// conversion the Kubernetes ecosystem expects (preserving numbers,
	// handling multiline strings, etc.).
	jsonBytes, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(jsonBytes); err != nil {
		return nil, fmt.Errorf("decode object: %w", err)
	}

	// If the YAML the user submitted is missing apiVersion/kind — common on
	// older cached YAML before 2.6.1 populated TypeMeta — fall back to the
	// GVK we were called with. The API server would otherwise reject the
	// request with "object has no kind", which surfaces as a confusing 502
	// on top of a reverse proxy.
	if obj.GroupVersionKind().Empty() {
		apiVersion := gvr.Version
		if gvr.Group != "" {
			apiVersion = gvr.Group + "/" + gvr.Version
		}
		obj.SetAPIVersion(apiVersion)
		obj.SetKind(kind)
	}

	// Guardrails so the user can't rename or move a resource via apply —
	// a kubectl apply with mismatched metadata is a common foot-gun; the
	// console refuses it rather than mutating the "wrong" object.
	if obj.GetName() != "" && obj.GetName() != name {
		return nil, fmt.Errorf("metadata.name %q does not match URL %q", obj.GetName(), name)
	}
	if obj.GetNamespace() != "" && obj.GetNamespace() != namespace {
		return nil, fmt.Errorf("metadata.namespace %q does not match URL %q", obj.GetNamespace(), namespace)
	}
	obj.SetName(name)
	if namespace != "" {
		obj.SetNamespace(namespace)
	}

	// managedFields clutter the YAML view and server-side apply strips them
	// anyway. Drop them so the request we send is the one the user sees.
	obj.SetManagedFields(nil)

	// resourceVersion is REQUIRED for Update, and the YAML we served already
	// contains the one we fetched. If the user wiped it they'll get a clear
	// error here rather than a confusing 409 later.
	if obj.GetResourceVersion() == "" {
		return nil, fmt.Errorf("metadata.resourceVersion is required (open the YAML again to pick it up)")
	}

	opts := metav1.UpdateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	// Namespace-scoped vs cluster-scoped: dynamic client picks the right
	// resource interface based on whether we chain .Namespace(ns) or not.
	var updated *unstructured.Unstructured
	if namespace == "" {
		updated, err = dyn.Resource(gvr).Update(ctx, obj, opts)
	} else {
		updated, err = dyn.Resource(gvr).Namespace(namespace).Update(ctx, obj, opts)
	}
	if err != nil {
		return nil, err
	}

	// Round-trip to YAML: the server returned a defaulted object (fields
	// like status timestamps, generation, etc.). This is what the user is
	// about to see on the right side of the diff, so send it back.
	updated.SetManagedFields(nil)
	if gvr.Resource == "secrets" {
		// Same readable shape the editor was opened with (see secretyaml.go).
		yamlOut, err := editableSecretFromMap(updated.Object)
		if err != nil {
			return nil, err
		}
		return &ApplyResult{AppliedYAML: string(yamlOut), DryRun: dryRun}, nil
	}
	jsonOut, err := updated.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	yamlOut, err := yaml.JSONToYAML(jsonOut)
	if err != nil {
		return nil, fmt.Errorf("render yaml: %w", err)
	}

	return &ApplyResult{
		AppliedYAML: string(yamlOut),
		DryRun:      dryRun,
	}, nil
}
