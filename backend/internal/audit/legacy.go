package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"k8s-dashboard/backend/internal/models"
)

// legacyActions maps pre-2.17 actions (outcome suffix removed) to resource
// type and verb. Plain reads (list / get / logs) and "<kind>.apply" are
// handled in UpgradeLegacyEntry.
var legacyActions = map[string][2]string{
	"login":                           {KindUser, VerbLogin},
	"login.azure":                     {KindUser, VerbLogin},
	"change_password":                 {KindUser, VerbChangePassword},
	"user.password_reset":             {KindUser, VerbResetPassword},
	"user.auto_provision":             {KindUser, VerbCreate},
	"admin.update_groups":             {KindUser, VerbUpdate},
	"admin.update_roles":              {KindGroup, VerbUpdate},
	"admin.add_permission":            {KindPermission, VerbCreate},
	"admin.delete_permission":         {KindPermission, VerbDelete},
	"admin.import":                    {KindUser, VerbImport},
	"session.revoke_all":              {KindSession, VerbRevoke},
	"secret.yaml.view":                {"secret", VerbViewYAML},
	"recording.settings.update":       {KindSettings, VerbUpdate},
	"recording.evicted":               {KindRecording, VerbEvict},
	"pod.exec.start":                  {"pod", VerbExec},
	"pod.exec.end":                    {"pod", VerbExec},
	"pod.exec.session.recorded":       {KindRecording, VerbCreate},
	"pod.exec.session.record_skipped": {KindRecording, VerbCreate},
	"pod.exec.session.record_failed":  {KindRecording, VerbCreate},
	"view.save":                       {KindSavedView, VerbCreate},
	"view.share":                      {KindSavedView, VerbShare},
	"view.delete":                     {KindSavedView, VerbDelete},
	"view.change":                     {KindSavedView, VerbUpdate},
}

// legacyAdminKinds maps the resource type of pre-2.17 admin.create / update /
// delete / export rows.
var legacyAdminKinds = map[string]string{
	"users": KindUser, "groups": KindGroup, "roles": KindRole,
	"ldap": KindSettings, "azure_ad": KindSettings, "session": KindSettings, "customization": KindSettings,
}

// UpgradeLegacyEntry rewrites a pre-2.17 row: action split into
// "<kind>.<verb>" + outcome, plural resource types made singular, "-"
// namespaces cleared. The resource name keeps any "(k=v)" suffix it had.
func UpgradeLegacyEntry(e models.AuditLog) models.AuditLog {
	action, outcome := SplitLegacyAction(e.Action)
	if outcome == "" {
		outcome = Success
	}
	switch action {
	case "pod.exec.session.record_skipped", "pod.exec.session.record_failed":
		outcome = Failed
	}
	kind, verb := Kind(e.ResourceType), ""
	switch {
	case action == VerbList || action == VerbGet || action == VerbLogs:
		verb = action
	case strings.HasSuffix(action, ".apply"):
		kind, verb = Kind(strings.TrimSuffix(action, ".apply")), VerbApply
	case strings.HasPrefix(action, "admin.") && legacyActions[action] == [2]string{}:
		verb = strings.TrimPrefix(action, "admin.")
		if k, ok := legacyAdminKinds[e.ResourceType]; ok {
			kind = k
		}
		if kind == KindSettings {
			if e.ResourceName == "logo_removed" {
				verb = VerbDelete
			}
			name := e.ResourceType
			if name == "customization" {
				name = "logo"
			}
			e.ResourceName = name
		}
	default:
		if m, ok := legacyActions[action]; ok {
			kind, verb = m[0], m[1]
			if action == "recording.settings.update" {
				e.ResourceName = "recording"
			}
		} else if i := strings.Index(action, "."); i > 0 {
			kind, verb = action[:i], strings.ReplaceAll(action[i+1:], ".", "_")
		} else {
			verb = action
		}
	}
	e.ResourceType = kind
	e.Verb = verb
	e.Action = kind + "." + verb
	e.Outcome = outcome
	if e.Namespace == "-" {
		e.Namespace = ""
	}
	return e
}

// UpgradeLegacy rewrites every pre-2.17 audit row in batches. Safe to run on
// every start: once done there is nothing left to select.
func (l *Logger) UpgradeLegacy(ctx context.Context) error {
	total := 0
	for {
		rows, err := l.store.LegacyAuditLogs(ctx, 1000)
		if err != nil {
			return fmt.Errorf("read legacy audit rows: %w", err)
		}
		if len(rows) == 0 {
			break
		}
		for i := range rows {
			rows[i] = UpgradeLegacyEntry(rows[i])
		}
		if err := l.store.UpgradeAuditLogs(ctx, rows); err != nil {
			return fmt.Errorf("upgrade legacy audit rows: %w", err)
		}
		total += len(rows)
	}
	if total > 0 {
		slog.Info("audit rows upgraded to 2.17 format", slog.Int("rows", total))
	}
	return nil
}
