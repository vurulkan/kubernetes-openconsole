package audit

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// Verbs: what was done. Action is "<resource type>.<verb>".
const (
	VerbList           = "list"
	VerbGet            = "get"
	VerbLogs           = "logs"
	VerbExec           = "exec"
	VerbRestart        = "restart"
	VerbScale          = "scale"
	VerbApply          = "apply"
	VerbViewYAML       = "view_yaml"
	VerbReveal         = "reveal"
	VerbView           = "view"
	VerbDownload       = "download"
	VerbCreate         = "create"
	VerbUpdate         = "update"
	VerbDelete         = "delete"
	VerbShare          = "share"
	VerbSelect         = "select"
	VerbActivate       = "activate"
	VerbDeactivate     = "deactivate"
	VerbRevoke         = "revoke"
	VerbExport         = "export"
	VerbImport         = "import"
	VerbLogin          = "login"
	VerbChangePassword = "change_password"
	VerbResetPassword  = "reset_password"
	VerbEvict          = "evict"
	VerbPurge          = "purge"
	VerbViewOverview   = "view_overview"
)

// Verbs lists every verb, for validation and the Admin → Audit filter.
var Verbs = []string{
	VerbList, VerbGet, VerbLogs, VerbExec, VerbRestart, VerbScale, VerbApply,
	VerbViewYAML, VerbReveal, VerbView, VerbDownload, VerbCreate, VerbUpdate,
	VerbDelete, VerbShare, VerbSelect, VerbActivate, VerbDeactivate, VerbRevoke,
	VerbExport, VerbImport, VerbLogin, VerbChangePassword, VerbResetPassword,
	VerbEvict, VerbPurge, VerbViewOverview,
}

// Outcomes: how it ended.
const (
	Success     = "success"
	Denied      = "denied"
	Failed      = "failed"
	RateLimited = "rate_limited"
	Locked      = "locked"
)

// Outcomes lists every outcome.
var Outcomes = []string{Success, Denied, Failed, RateLimited, Locked}

// Resource types that are not Kubernetes objects.
const (
	KindUser       = "user"
	KindGroup      = "group"
	KindRole       = "role"
	KindPermission = "permission"
	KindCluster    = "cluster"
	KindSettings   = "settings"
	KindSession    = "session"
	KindRecording  = "recording"
	KindSavedView  = "saved_view"
)

// kubeKinds maps the plural resource names used by RBAC grants and URLs to
// the singular resource type audit records carry.
var kubeKinds = map[string]string{
	"namespaces":   "namespace",
	"pods":         "pod",
	"deployments":  "deployment",
	"daemonsets":   "daemonset",
	"statefulsets": "statefulset",
	"hpas":         "hpa",
	"services":     "service",
	"configmaps":   "configmap",
	"secrets":      "secret",
	"ingresses":    "ingress",
	"cronjobs":     "cronjob",
	"jobs":         "job",
}

// Kind returns the singular resource type for an RBAC resource ("deployments"
// → "deployment"); other values are returned unchanged.
func Kind(resource string) string {
	if k, ok := kubeKinds[resource]; ok {
		return k
	}
	return resource
}

// IsKubeKind reports whether kind is a Kubernetes object, i.e. an action on
// it runs against the request's cluster.
func IsKubeKind(kind string) bool { return kubeKindSet[kind] }

var kubeKindSet = func() map[string]bool {
	out := map[string]bool{}
	for _, k := range kubeKinds {
		out[k] = true
	}
	return out
}()

// DetailType is the Elasticsearch type of a details key (see
// deploy/elk/openconsole@mappings.component-template.json).
type DetailType string

const (
	Keyword DetailType = "keyword"
	Text    DetailType = "text"
	Long    DetailType = "long"
	Bool    DetailType = "boolean"
	Date    DetailType = "date"
)

// DetailKeys are the only keys Details may use. Each lands in the console
// line as its own field (openconsole.<key> in ECS, except error →
// error.message), so the set is fixed and typed. Never add a key that
// carries a secret value, a YAML body, a password or a token.
var DetailKeys = map[string]DetailType{
	// deployment / statefulset
	"restarted_at":  Date,
	"replicas_from": Long,
	"replicas_to":   Long,
	// logs / exec
	"pod":          Keyword,
	"pods":         Long,
	"container":    Keyword,
	"previous":     Bool, // logs of the previous (crashed) container
	"command":      Keyword,
	"phase":        Keyword, // exec: start | end
	"exit_code":    Long,
	"bytes_in":     Long,
	"bytes_out":    Long,
	"duration_ms":  Long,
	"max_sessions": Long,
	// secrets (the key name, never the value)
	"key": Keyword,
	// YAML apply: hashes, not bodies
	"dry_run":   Bool,
	"yaml_from": Keyword,
	"yaml_to":   Keyword,
	// recordings
	"session_id":      Keyword,
	"owner":           Keyword,
	"started_at":      Date,
	"size_bytes":      Long,
	"truncate_reason": Keyword,
	"retention_days":  Long,
	// sign-in and accounts
	"login_method":     Keyword, // local | ldap | azure
	"account_source":   Keyword, // the target account's source
	"linked_by":        Keyword,
	"signed_in_as":     Keyword,
	"must_change":      Bool,
	"auto_provisioned": Bool,
	"is_admin":         Bool,
	"is_active":        Bool,
	"groups":           Long,
	"count":            Long,
	"all":              Bool,
	// admin
	"id":      Long,
	"role":    Keyword,
	"grant":   Keyword, // resource:action of a permission
	"changed": Keyword, // what changed (array of field names), not the values
	"shared":  Bool,
	"summary": Text,
	// failures
	"error": Text,
}

// D builds Details.
type D = map[string]any

// normalize fills Action / Outcome, keeps Details to registered keys and
// coerces their values to the registered type.
func normalize(e *models.AuditLog) {
	if e.Verb == "" {
		e.Verb = e.Action[strings.LastIndex(e.Action, ".")+1:]
	}
	if e.Action == "" {
		e.Action = e.ResourceType + "." + e.Verb
	}
	if e.Outcome == "" {
		e.Outcome = Success
	}
	if e.Namespace == "-" {
		e.Namespace = ""
	}
	if len(e.Details) == 0 {
		e.Details = nil
		return
	}
	for k, v := range e.Details {
		t, ok := DetailKeys[k]
		if !ok {
			slog.Warn("audit detail key not registered; dropped", slog.String("key", k), slog.String("action", e.Action))
			delete(e.Details, k)
			continue
		}
		if cv, ok := coerce(t, v); ok {
			e.Details[k] = cv
		} else {
			delete(e.Details, k)
		}
	}
	if len(e.Details) == 0 {
		e.Details = nil
	}
}

func coerce(t DetailType, v any) (any, bool) {
	switch t {
	case Long:
		switch n := v.(type) {
		case int:
			return int64(n), true
		case int32:
			return int64(n), true
		case int64:
			return n, true
		case float64: // decoded from JSON
			return int64(n), true
		}
		return nil, false
	case Bool:
		b, ok := v.(bool)
		return b, ok
	case Date:
		switch d := v.(type) {
		case time.Time:
			return d.UTC().Format(time.RFC3339), true
		case string:
			return d, d != ""
		}
		return nil, false
	default:
		switch s := v.(type) {
		case string:
			return s, s != ""
		case []string:
			return s, len(s) > 0
		case []any: // decoded from JSON
			return s, len(s) > 0
		case error:
			return s.Error(), true
		}
		return fmt.Sprint(v), true
	}
}

// detailAttrs returns the details as slog attributes in key order.
func detailAttrs(d map[string]any) []slog.Attr {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]slog.Attr, 0, len(keys))
	for _, k := range keys {
		out = append(out, slog.Any(k, d[k]))
	}
	return out
}

// legacyOutcomes are the suffixes pre-2.17 actions carried.
var legacyOutcomes = map[string]bool{Success: true, Denied: true, Failed: true, RateLimited: true, Locked: true}

// SplitLegacyAction splits a pre-2.17 style "<action>.<outcome>"
// (deployment.restart.success) into action and outcome; outcome is "" when
// the last segment is not an outcome.
func SplitLegacyAction(a string) (action, outcome string) {
	if i := strings.LastIndex(a, "."); i > 0 && legacyOutcomes[a[i+1:]] {
		return a[:i], a[i+1:]
	}
	return a, ""
}
