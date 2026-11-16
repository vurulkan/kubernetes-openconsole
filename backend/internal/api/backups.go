package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/backup"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

// Admin → Backups: copies of the database (backup.Manager). A copy holds
// every stored credential, so downloading is off unless the operator sets
// BACKUP_ALLOW_DOWNLOAD=true on the Deployment, and an API key never may.

const reasonBackupDownloadOff = problem.BackupDownloadDisabled

// SetBackups gives the server its backup manager, the interval of scheduled
// copies and BACKUP_ALLOW_DOWNLOAD (nil manager = the screen says backups are
// not set up).
func (s *Server) SetBackups(m *backup.Manager, interval time.Duration, allowDownload bool) {
	s.backups, s.backupInterval, s.backupDownload = m, interval, allowDownload
}

// SetKeyExternal tells Admin → Backups whether the encryption key lives
// outside the database (ENCRYPTION_KEY_FILE), i.e. whether a copy alone
// reveals the credentials.
func (s *Server) SetKeyExternal(v bool) { s.keyExternal = v }

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeErrorDetail(w, http.StatusServiceUnavailable, problem.NotConfigured, "backups are not set up")
		return
	}
	list, err := s.backups.List()
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to list backups")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           list,
		"dir":             s.backups.Dir(),
		"keep":            s.backups.Keep(),
		"intervalSeconds": int(s.backupInterval / time.Second),
		"allowDownload":   s.backupDownload,
		"keyExternal":     s.keyExternal,
	})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeErrorDetail(w, http.StatusServiceUnavailable, problem.NotConfigured, "backups are not set up")
		return
	}
	extendWriteDeadline(w, 10*time.Minute) // a large database on slow storage
	info, err := s.backups.Create(r.Context(), "manual")
	if err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, Outcome: audit.Failed, Reason: failReason(err),
			ResourceType: audit.KindBackup, ResourceName: "*", Details: failDetails(err, nil)})
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "backup failed: "+err.Error())
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindBackup, ResourceName: info.Name,
		Details: audit.D{"size_bytes": info.SizeBytes}})
	writeJSON(w, http.StatusCreated, info)
}

// handleDownloadBackup sends one copy. Refused (403) unless
// BACKUP_ALLOW_DOWNLOAD=true; then every copy can be downloaded, older ones
// included.
func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	e := models.AuditLog{Verb: audit.VerbDownload, ResourceType: audit.KindBackup, ResourceName: name}
	if s.denyAPIKey(w, r, e) {
		return
	}
	if s.backups == nil {
		writeErrorDetail(w, http.StatusServiceUnavailable, problem.NotConfigured, "backups are not set up")
		return
	}
	if !s.backupDownload {
		e.Outcome, e.Reason = audit.Denied, reasonBackupDownloadOff
		s.auditEvent(r, e)
		writeError(w, http.StatusForbidden, reasonBackupDownloadOff)
		return
	}
	f, info, err := s.backups.Open(name)
	if errors.Is(err, backup.ErrNotFound) {
		e.Outcome, e.Reason = audit.Failed, "not_found"
		s.auditEvent(r, e)
		writeErrorDetail(w, http.StatusNotFound, problem.NotFound, "backup not found")
		return
	}
	if err != nil {
		e.Outcome, e.Reason, e.Details = audit.Failed, failReason(err), failDetails(err, nil)
		s.auditEvent(r, e)
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to open backup")
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
