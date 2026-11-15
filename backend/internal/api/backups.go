package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/models"
)

// Admin → Backups: copies of the database (backup.Manager). A copy holds
// every stored credential, so downloading is off until an admin turns it on,
// and an API key may neither download nor change that setting.

const reasonBackupDownloadOff = "backup_download_disabled"

// SetBackups gives the server its backup manager and the interval of
// scheduled copies (nil manager = the screen says backups are not set up).
func (s *Server) SetBackups(m *backup.Manager, interval time.Duration) {
	s.backups, s.backupInterval = m, interval
}

// SetKeyExternal tells Admin → Backups whether the encryption key lives
// outside the database (ENCRYPTION_KEY_FILE), i.e. whether a copy alone
// reveals the credentials.
func (s *Server) SetKeyExternal(v bool) { s.keyExternal = v }

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not set up")
		return
	}
	list, err := s.backups.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list backups")
		return
	}
	allow, err := s.store.BackupDownloadAllowed(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read backup settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           list,
		"dir":             s.backups.Dir(),
		"keep":            s.backups.Keep(),
		"intervalSeconds": int(s.backupInterval / time.Second),
		"allowDownload":   allow,
		"keyExternal":     s.keyExternal,
	})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not set up")
		return
	}
	extendWriteDeadline(w, 10*time.Minute) // a large database on slow storage
	info, err := s.backups.Create(r.Context(), "manual")
	if err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, Outcome: audit.Failed, Reason: failReason(err),
			ResourceType: audit.KindBackup, ResourceName: "*", Details: failDetails(err, nil)})
		writeError(w, http.StatusInternalServerError, "backup failed: "+err.Error())
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindBackup, ResourceName: info.Name,
		Details: audit.D{"size_bytes": info.SizeBytes}})
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) handleUpdateBackupSettings(w http.ResponseWriter, r *http.Request) {
	e := models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindSettings, ResourceName: "backups"}
	if s.denyAPIKey(w, r, e) {
		return
	}
	var in struct {
		AllowDownload *bool `json:"allowDownload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.AllowDownload == nil {
		writeError(w, http.StatusBadRequest, `the body must be {"allowDownload": true|false}`)
		return
	}
	if err := s.store.SetBackupDownloadAllowed(r.Context(), *in.AllowDownload); err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "failed to save backup settings")
		return
	}
	e.Details = audit.D{"changed": []string{"allow_download"}, "summary": "allow_download=" + strconv.FormatBool(*in.AllowDownload)}
	s.auditEvent(r, e)
	writeJSON(w, http.StatusOK, map[string]bool{"allowDownload": *in.AllowDownload})
}

// handleDownloadBackup sends one copy. Refused (403) while downloading is
// off; once it is on, every copy can be downloaded, older ones included.
func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	e := models.AuditLog{Verb: audit.VerbDownload, ResourceType: audit.KindBackup, ResourceName: name}
	if s.denyAPIKey(w, r, e) {
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not set up")
		return
	}
	allow, err := s.store.BackupDownloadAllowed(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read backup settings")
		return
	}
	if !allow {
		e.Outcome, e.Reason = audit.Denied, reasonBackupDownloadOff
		s.auditEvent(r, e)
		writeError(w, http.StatusForbidden, reasonBackupDownloadOff)
		return
	}
	f, info, err := s.backups.Open(name)
	if errors.Is(err, backup.ErrNotFound) {
		e.Outcome, e.Reason = audit.Failed, "not_found"
		s.auditEvent(r, e)
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeError(w, http.StatusInternalServerError, "failed to open backup")
		return
	}
	defer f.Close()
	e.Details = audit.D{"size_bytes": info.SizeBytes}
	s.auditEvent(r, e)
	extendWriteDeadline(w, 30*time.Minute)
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+info.Name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", info.CreatedAt, f)
}
