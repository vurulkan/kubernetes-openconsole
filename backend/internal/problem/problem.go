// Package problem writes every error answer of the API the same way: RFC 9457
// problem details (application/problem+json) with one extension member,
// `error`, the reason code a client switches on. `error` was the whole body
// before 2.23.x ({"error": "forbidden"}), so clients that read it keep working.
//
//	{"type": "about:blank", "title": "Forbidden", "status": 403,
//	 "error": "forbidden", "detail": "…"}
//
// `detail` is optional English text for a human (which field, which name);
// clients never parse it. A new code goes into Codes (the OpenAPI error schema
// and the UI's sentences are checked against it).
package problem

import (
	"encoding/json"
	"net/http"
)

// The reason codes. Keep the list in Codes in step.
const (
	Unauthorized           = "unauthorized"
	APIKeyExpired          = "api_key_expired"
	APIKeyRevoked          = "api_key_revoked"
	PasswordChangeRequired = "password_change_required"
	Forbidden              = "forbidden"
	AdminOnly              = "admin_only"
	FeatureDisabled        = "feature_disabled"
	APIKeyNotAllowed       = "api_key_not_allowed"
	APIAccessPolicy        = "api_access_policy"
	APIAccessOff           = "api_access_off"
	BackupDownloadDisabled = "backup_download_disabled"
	RateLimited            = "rate_limited"
	TooManySessions        = "too_many_sessions"
	NotFound               = "not_found"
	MethodNotAllowed       = "method_not_allowed"
	InvalidID              = "invalid_id"
	InvalidBody            = "invalid_body"
	InvalidInput           = "invalid_input"
	BodyTooLarge           = "body_too_large"
	Conflict               = "conflict"
	WrongPassword          = "wrong_password"
	WeakPassword           = "weak_password"
	PasswordUnchanged      = "password_unchanged"
	CannotDeleteSelf       = "cannot_delete_self"
	KubeconfigUnsupported  = "kubeconfig_unsupported"
	ClusterInvalid         = "cluster_invalid"
	ClusterForbidden       = "cluster_forbidden"
	ClusterTimeout         = "cluster_timeout"
	ClusterUnreachable     = "cluster_unreachable"
	ClusterError           = "cluster_error"
	NotConnected           = "not_connected"
	NotConfigured          = "not_configured"
	ConnectionFailed       = "connection_failed"
	ExecFailed             = "exec_failed"
	SignInFailed           = "sign_in_failed"
	RecordingUnavailable   = "recording_unavailable"
	InternalError          = "internal_error"
)

// Code is one reason code with what it means, for the API description.
type Code struct {
	Code string
	Doc  string
}

// Codes is every reason code the API answers with.
var Codes = []Code{
	{Unauthorized, "Not signed in, or the session or API key is no longer valid (unknown, signed out, owner deactivated)."},
	{APIKeyExpired, "The API key has expired."},
	{APIKeyRevoked, "The API key was revoked."},
	{PasswordChangeRequired, "The account must change its password before it can do anything else."},
	{Forbidden, "Your roles don't allow this action."},
	{AdminOnly, "Only an administrator may do this."},
	{FeatureDisabled, "The feature is switched off on this server (FEATURE_* setting)."},
	{APIKeyNotAllowed, "This can't be done with an API key; sign in to the web console."},
	{APIAccessPolicy, "The key's owner may do this, but the administrator's API access policy doesn't allow it with a key."},
	{APIAccessOff, "API access is switched off for the key's owner."},
	{BackupDownloadDisabled, "Backup downloads are switched off (BACKUP_ALLOW_DOWNLOAD)."},
	{RateLimited, "Too many requests; wait and retry (see Retry-After)."},
	{TooManySessions, "Too many shells open at once for this user."},
	{NotFound, "The object or path doesn't exist."},
	{MethodNotAllowed, "The path exists but not with this HTTP method."},
	{InvalidID, "An id in the path isn't a number."},
	{InvalidBody, "The request body is missing or isn't valid JSON of the expected shape."},
	{InvalidInput, "A value in the request isn't accepted; detail says which."},
	{BodyTooLarge, "The request body is over the size limit."},
	{Conflict, "The change conflicts with the current state (a name that exists, a revoked key, a recording still running)."},
	{WrongPassword, "The current password is wrong."},
	{WeakPassword, "The new password doesn't meet the password policy; detail says why."},
	{PasswordUnchanged, "The new password must differ from the current one."},
	{CannotDeleteSelf, "You can't delete your own account."},
	{KubeconfigUnsupported, "The kubeconfig runs a program, uses an auth provider or points to a file; only inline credentials are accepted."},
	{ClusterInvalid, "The cluster credentials were refused or the API server couldn't be reached; detail says why."},
	{ClusterForbidden, "OpenConsole's own account on the cluster may not read this (its ClusterRole)."},
	{ClusterTimeout, "The cluster's API server didn't answer in time."},
	{ClusterUnreachable, "The cluster's API server can't be reached, or it refused OpenConsole's credentials."},
	{ClusterError, "The cluster's API server refused the change; detail has its message."},
	{NotConnected, "There is no connection to the cluster."},
	{ExecFailed, "The command could not be started in the container (no such program, container not running)."},
	{ConnectionFailed, "A connection test or directory search (LDAP, Azure AD) failed; detail has the error."},
	{NotConfigured, "The feature isn't set up on this server (backups, Azure AD, …)."},
	{SignInFailed, "The external sign-in (Azure AD) failed or doesn't match this account."},
	{RecordingUnavailable, "The shell can't be recorded right now, and this session must be; try again later."},
	{InternalError, "The server failed; the request id in the server log has the cause."},
}

// Known reports whether code is in Codes.
func Known(code string) bool {
	for _, c := range Codes {
		if c.Code == code {
			return true
		}
	}
	return false
}

// Body is the JSON of an error answer.
type Body struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// Write answers status with code (one of the constants above) and an optional
// English detail.
func Write(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Body{Type: "about:blank", Title: http.StatusText(status), Status: status, Error: code, Detail: detail})
}
