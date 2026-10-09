package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
)

// Secrets are exposed in two tiers:
//   - secrets:list / secrets:get return metadata only — name, type, labels,
//     key names and value sizes. Values never leave the server on these.
//   - secrets:reveal returns ONE key's value per request, and every attempt
//     (success / denied / failed) is audited with the key name.
//   - secrets:edit opens the YAML editor (values shown as plain-text
//     stringData) and applies changes through the shared YAML apply flow.
//     Opening the YAML exposes every value, so it is audited as
//     secret.yaml.view.{success,denied,failed}.

type secretKey struct {
	Name string `json:"name"`
	Size int    `json:"size"` // decoded bytes
}

type secretSummary struct {
	Metadata  secretMeta  `json:"metadata"`
	Type      string      `json:"type"`
	Immutable bool        `json:"immutable"`
	Keys      []secretKey `json:"keys"`
}

// secretMeta mirrors the metadata fields the dashboard reads from every other
// resource (name, created, labels) so cards / list rows render the same way.
type secretMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

// Annotations that can embed the full secret (kubectl apply keeps the last
// applied object, data included) are dropped from the summary.
var secretAnnotationDenylist = map[string]bool{
	"kubectl.kubernetes.io/last-applied-configuration": true,
}

func summarizeSecret(sec *corev1.Secret) secretSummary {
	keys := make([]secretKey, 0, len(sec.Data)+len(sec.StringData))
	for k, v := range sec.Data {
		keys = append(keys, secretKey{Name: k, Size: len(v)})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	var annotations map[string]string
	for k, v := range sec.Annotations {
		if secretAnnotationDenylist[k] {
			continue
		}
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[k] = v
	}
	return secretSummary{
		Metadata: secretMeta{
			Name:              sec.Name,
			Namespace:         sec.Namespace,
			UID:               string(sec.UID),
			CreationTimestamp: sec.CreationTimestamp.Time,
			Labels:            sec.Labels,
			Annotations:       annotations,
		},
		Type:      string(sec.Type),
		Immutable: sec.Immutable != nil && *sec.Immutable,
		Keys:      keys,
	}
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "secrets", "list")
	if !ok {
		return
	}
	items, err := s.resources.ListSecrets(r.Context(), namespace)
	if err != nil {
		writeKubeError(w, err)
		return
	}
	out := make([]secretSummary, 0, len(items))
	for i := range items {
		out = append(out, summarizeSecret(&items[i]))
	}
	s.recordAudit(r, "list", namespace, "secrets", "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request) {
	namespace, ok := s.requirePermission(w, r, "secrets", "get")
	if !ok {
		return
	}
	sec, err := s.resources.GetSecret(r.Context(), namespace, chi.URLParam(r, "name"))
	if err != nil {
		writeKubeError(w, err)
		return
	}
	s.recordAudit(r, "get", namespace, "secrets", sec.Name)
	writeJSON(w, http.StatusOK, summarizeSecret(sec))
}

// handleSecretReveal returns a single key's value. POST so the value never
// sits in a URL (proxy logs, browser history) and is never cached.
func (s *Server) handleSecretReveal(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	requestID := logpkg.RequestIDFrom(r.Context())
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !s.can(r.Context(), user.ID, namespace, "secrets", "reveal") {
		s.recordSecretRevealAudit(user.Username, namespace, name, body.Key, "denied", "", requestID)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	sec, err := s.resources.GetSecret(r.Context(), namespace, name)
	if err != nil {
		s.recordSecretRevealAudit(user.Username, namespace, name, body.Key, "failed", err.Error(), requestID)
		writeKubeError(w, err)
		return
	}
	value, found := sec.Data[body.Key]
	if !found {
		s.recordSecretRevealAudit(user.Username, namespace, name, body.Key, "failed", "key_not_found", requestID)
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	s.recordSecretRevealAudit(user.Username, namespace, name, body.Key, "success", "", requestID)
	w.Header().Set("Cache-Control", "no-store")
	// Text values come back as-is; binary values (keystores, certs in DER)
	// as base64 with a flag so the UI can say so instead of printing mojibake.
	if utf8.Valid(value) {
		writeJSON(w, http.StatusOK, map[string]any{"key": body.Key, "value": string(value), "encoding": "text"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key": body.Key, "value": base64.StdEncoding.EncodeToString(value), "encoding": "base64",
	})
}

// handleSecretYAML serves the editable YAML. It requires secrets:edit (not
// just get) because the document carries every value.
func (s *Server) handleSecretYAML(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	requestID := logpkg.RequestIDFrom(r.Context())
	if !s.can(r.Context(), user.ID, namespace, "secrets", "edit") {
		s.recordSecretAudit(user.Username, namespace, name, "secret.yaml.view.denied", "", requestID)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	sec, err := s.resources.GetSecret(r.Context(), namespace, name)
	if err != nil {
		s.recordSecretAudit(user.Username, namespace, name, "secret.yaml.view.failed", err.Error(), requestID)
		writeKubeError(w, err)
		return
	}
	out, err := kube.EditableSecretYAML(sec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render yaml")
		return
	}
	s.recordSecretAudit(user.Username, namespace, name, "secret.yaml.view.success", "", requestID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(out)})
}

func (s *Server) recordSecretAudit(user, namespace, name, action, detail, requestID string) {
	resource := name
	if detail != "" {
		resource += " (" + detail + ")"
	}
	go s.audit.Record(s.auditCtxFromID(requestID), models.AuditLog{
		User:         user,
		Action:       action,
		Namespace:    namespace,
		ResourceType: "secret",
		ResourceName: resource,
	})
	slog.Info("secret.action",
		slog.String("event", action),
		slog.String("user", user),
		slog.String("namespace", namespace),
		slog.String("secret", name),
		slog.String("details", detail),
		slog.String("request_id", requestID),
	)
}

func (s *Server) recordSecretRevealAudit(user, namespace, name, key, outcome, detail, requestID string) {
	resource := name + " (key=" + key
	if detail != "" {
		resource += ";" + detail
	}
	resource += ")"
	go s.audit.Record(s.auditCtxFromID(requestID), models.AuditLog{
		User:         user,
		Action:       "secret.reveal." + outcome,
		Namespace:    namespace,
		ResourceType: "secret",
		ResourceName: resource,
	})
	slog.Info("secret.action",
		slog.String("event", "secret.reveal."+outcome),
		slog.String("user", user),
		slog.String("namespace", namespace),
		slog.String("secret", name),
		slog.String("key", key),
		slog.String("details", detail),
		slog.String("request_id", requestID),
	)
}

// writeKubeError reuses httpStatusFor for API-server errors and reports
// anything else (no active cluster, client not ready) as 503. A Kubernetes
// 403 gets a hint: the ServiceAccount's ClusterRole lacks secrets access.
func writeKubeError(w http.ResponseWriter, err error) {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		writeError(w, http.StatusServiceUnavailable, "kubernetes client not ready")
		return
	}
	code := httpStatusFor(err)
	if code == http.StatusForbidden {
		writeError(w, code, "the OpenConsole ServiceAccount is not allowed to read secrets here (check the ClusterRole)")
		return
	}
	writeError(w, code, err.Error())
}
