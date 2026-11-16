package api

import (
	"log/slog"
	"net/http"
	"sort"
	"strings"
)

// Feature flags let an operator switch risky capabilities off for everyone —
// admins included — with an env var (FEATURE_<NAME>=false), e.g. to keep pod
// shells closed in production for a while. A disabled feature is enforced
// where permissions are checked (s.can / requirePermission), so every
// endpoint refuses it and audits the denial, and it is removed from the
// permissions the UI receives, so its buttons disappear.
const (
	FeaturePodExec         = "pod_exec"         // pods:exec
	FeatureYAMLEdit        = "yaml_edit"        // {resource}:edit except secrets
	FeatureWorkloadActions = "workload_actions" // deployments:restart|scale, statefulsets:scale
	FeatureSecrets         = "secrets"          // every secrets:* action
	FeatureSecretReveal    = "secret_reveal"    // secrets:reveal
	FeatureSecretEdit      = "secret_edit"      // secrets:edit
	FeatureAPIKeys         = "api_keys"         // API keys: the screen, the endpoints and signing in with one
)

// AllFeatures lists every flag, for docs and GET /api/features.
var AllFeatures = []string{FeaturePodExec, FeatureYAMLEdit, FeatureWorkloadActions, FeatureSecrets, FeatureSecretReveal, FeatureSecretEdit, FeatureAPIKeys}

// FeatureDocs says what FEATURE_<NAME>=false turns off (cmd/docgen, the
// Environment variables page). Every flag in AllFeatures needs one.
var FeatureDocs = map[string]string{
	FeaturePodExec:         "pod shell and one-command exec (`pods:exec`)",
	FeatureYAMLEdit:        "YAML edit / apply on every resource except Secrets (`{resource}:edit`)",
	FeatureWorkloadActions: "Deployment restart and scale, StatefulSet scale",
	FeatureSecrets:         "the whole Secrets tab (every `secrets:*`)",
	FeatureSecretReveal:    "revealing secret values (`secrets:reveal`)",
	FeatureSecretEdit:      "editing Secrets (`secrets:edit`)",
	FeatureAPIKeys:         "API keys: the page, the `/api/me/api-keys` endpoints and signing in with a key (a key then gets 401)",
}

// SetDisabledFeatures applies the operator's flags and logs what is off. Call
// it before serving.
func (s *Server) SetDisabledFeatures(off []string) {
	m := map[string]bool{}
	for _, f := range off {
		m[f] = true
	}
	s.disabledFeatures = m
	if len(off) > 0 {
		sorted := append([]string(nil), off...)
		sort.Strings(sorted)
		slog.Info("features disabled", slog.String("features", strings.Join(sorted, ",")))
	}
}

func (s *Server) featureEnabled(name string) bool { return !s.disabledFeatures[name] }

// featureAllows reports whether the flags permit resource:action at all.
func (s *Server) featureAllows(resource, action string) bool {
	resource, action = strings.ToLower(resource), strings.ToLower(action)
	if resource == "secrets" {
		if !s.featureEnabled(FeatureSecrets) {
			return false
		}
		switch action {
		case "reveal":
			return s.featureEnabled(FeatureSecretReveal)
		case "edit":
			return s.featureEnabled(FeatureSecretEdit)
		}
		return true
	}
	switch {
	case resource == "pods" && action == "exec":
		return s.featureEnabled(FeaturePodExec)
	case action == "edit":
		return s.featureEnabled(FeatureYAMLEdit)
	case (resource == "deployments" && (action == "restart" || action == "scale")) ||
		(resource == "statefulsets" && action == "scale"):
		return s.featureEnabled(FeatureWorkloadActions)
	}
	return true
}

// filterByFeatures drops disabled actions (and resources left empty) from a
// resource → actions map before it reaches the UI.
func (s *Server) filterByFeatures(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for resource, actions := range in {
		kept := make([]string, 0, len(actions))
		for _, a := range actions {
			if s.featureAllows(resource, a) {
				kept = append(kept, a)
			}
		}
		if len(kept) > 0 {
			out[resource] = kept
		}
	}
	return out
}

// handleFeatures returns every flag with its state.
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request) {
	out := make(map[string]bool, len(AllFeatures))
	for _, f := range AllFeatures {
		out[f] = s.featureEnabled(f)
	}
	writeJSON(w, http.StatusOK, map[string]any{"features": out})
}
