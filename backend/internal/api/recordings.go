package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/recording"
)

// Admin-only endpoints for pod exec session recordings. Reads sit behind
// requireAdmin; writes (delete, settings) check admin in the handler so a
// denied attempt still lands in the audit log.

func (s *Server) handleListRecordings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := models.RecordingFilter{
		User:      q.Get("user"),
		Cluster:   q.Get("cluster"),
		Namespace: q.Get("namespace"),
		Pod:       q.Get("pod"),
		From:      parseTimeParam(q.Get("from")),
		To:        parseTimeParam(q.Get("to")),
	}
	// A bare date for `to` means "through the end of that day".
	if f.To != nil && len(q.Get("to")) == len("2006-01-02") {
		end := f.To.Add(24*time.Hour - time.Nanosecond)
		f.To = &end
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	items, total, err := s.recorder.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list recordings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recordingFromURL(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleRecordingCast streams the .cast file. Viewing is audited because a
// recording can contain anything the shell printed, secrets included.
func (s *Server) handleRecordingCast(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recordingFromURL(w, r)
	if !ok {
		return
	}
	f, err := os.Open(rec.Path)
	if err != nil {
		writeError(w, http.StatusNotFound, "recording file missing")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to stat recording")
		return
	}

	action := "recording.view"
	if r.URL.Query().Get("download") == "1" {
		action = "recording.download"
		w.Header().Set("Content-Disposition", `attachment; filename="`+recordingFilename(rec)+`"`)
	}
	user, _ := s.userForRequest(r)
	s.recordRecordingAudit(r, userName(user), action, rec, "")

	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", info.ModTime(), f)
}

func (s *Server) handleDeleteRecording(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	stub := &models.SessionRecording{ID: id, Namespace: "-", Pod: "id:" + strconv.Itoa(id)}
	if !user.IsAdmin || user.MustChangePassword {
		s.recordRecordingAudit(r, user.Username, "recording.delete.denied", stub, "")
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	rec, err := s.recorder.Delete(r.Context(), id)
	switch {
	case errors.Is(err, recording.ErrNotFound):
		writeError(w, http.StatusNotFound, "recording not found")
		return
	case errors.Is(err, recording.ErrActive):
		s.recordRecordingAudit(r, user.Username, "recording.delete.failed", rec, "in_progress;"+recordingSummary(rec))
		writeError(w, http.StatusConflict, "recording is still in progress")
		return
	case err != nil:
		if rec == nil {
			rec = stub
		}
		s.recordRecordingAudit(r, user.Username, "recording.delete.failed", rec, err.Error()+";"+recordingSummary(rec))
		writeError(w, http.StatusInternalServerError, "failed to delete recording")
		return
	}
	// The row and file are gone after this, so the audit entry is the only
	// remaining trace of whose session it was.
	s.recordRecordingAudit(r, user.Username, "recording.delete.success", rec, recordingSummary(rec))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetRecordingSettings(w http.ResponseWriter, r *http.Request) {
	usage, err := s.recorder.Usage(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read recording usage")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": s.recorder.Settings(), "usage": usage})
}

func (s *Server) handleUpdateRecordingSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	requestID := logpkg.RequestIDFrom(r.Context())
	if !user.IsAdmin || user.MustChangePassword {
		s.recordSettingsAudit(user.Username, "denied", "", requestID)
		writeError(w, http.StatusForbidden, "admin only")
		return
	}
	var in models.RecordingSettings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	saved, err := s.recorder.UpdateSettings(r.Context(), in)
	if err != nil {
		var verr recording.ValidationError
		if errors.As(err, &verr) {
			s.recordSettingsAudit(user.Username, "failed", verr.Error(), requestID)
			writeError(w, http.StatusBadRequest, verr.Error())
			return
		}
		s.recordSettingsAudit(user.Username, "failed", err.Error(), requestID)
		writeError(w, http.StatusInternalServerError, "failed to save recording settings")
		return
	}
	s.recordSettingsAudit(user.Username, "success", settingsSummary(saved), requestID)
	writeJSON(w, http.StatusOK, map[string]any{"settings": saved})
}

func (s *Server) recordingFromURL(w http.ResponseWriter, r *http.Request) (*models.SessionRecording, bool) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return nil, false
	}
	rec, err := s.recorder.Get(r.Context(), id)
	if errors.Is(err, recording.ErrNotFound) {
		writeError(w, http.StatusNotFound, "recording not found")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load recording")
		return nil, false
	}
	return rec, true
}

func (s *Server) recordRecordingAudit(r *http.Request, user, action string, rec *models.SessionRecording, detail string) {
	name := rec.Pod
	if rec.SessionID != "" {
		name += " (session_id=" + rec.SessionID
		if detail != "" {
			name += ";" + detail
		}
		name += ")"
	} else if detail != "" {
		name += " (" + detail + ")"
	}
	go s.audit.Record(s.auditCtx(r), models.AuditLog{
		User:         user,
		Action:       action,
		Namespace:    rec.Namespace,
		ResourceType: "recording",
		ResourceName: name,
	})
	// Own console line, independent of LOG_INCLUDE_AUDIT, like the
	// deployment / settings actions.
	slog.Info("recording.action",
		slog.String("event", action),
		slog.String("user", user),
		slog.String("namespace", rec.Namespace),
		slog.String("pod", rec.Pod),
		slog.String("session_id", rec.SessionID),
		slog.String("details", detail),
		slog.String("request_id", logpkg.RequestIDFrom(r.Context())),
	)
}

// recordingSummary describes a recording for audit details: whose session it
// was, when, where and how big.
func recordingSummary(rec *models.SessionRecording) string {
	if rec == nil || rec.SessionID == "" {
		return ""
	}
	out := "owner=" + rec.User +
		";started=" + rec.StartedAt.UTC().Format(time.RFC3339) +
		";size=" + strconv.FormatInt(rec.SizeBytes, 10)
	if rec.Cluster != "" {
		out += ";cluster=" + rec.Cluster
	}
	if rec.Container != "" {
		out += ";container=" + rec.Container
	}
	return out
}

func (s *Server) recordSettingsAudit(user, outcome, detail, requestID string) {
	name := "settings"
	if detail != "" {
		name += " (" + detail + ")"
	}
	go s.audit.Record(s.auditCtxFromID(requestID), models.AuditLog{
		User:         user,
		Action:       "recording.settings.update." + outcome,
		Namespace:    "-",
		ResourceType: "recording",
		ResourceName: name,
	})
	slog.Info("recording.settings.update",
		slog.String("outcome", outcome),
		slog.String("user", user),
		slog.String("details", detail),
		slog.String("request_id", requestID),
	)
}

func settingsSummary(st models.RecordingSettings) string {
	return "enabled=" + strconv.FormatBool(st.Enabled) +
		";retention_days=" + strconv.Itoa(st.RetentionDays) +
		";max_session_mb=" + strconv.Itoa(st.MaxSessionMB) +
		";max_total_mb=" + strconv.Itoa(st.MaxTotalMB) +
		";min_free_mb=" + strconv.Itoa(st.MinFreeMB) +
		";disk_policy=" + st.DiskPolicy
}

// recordingFilename builds a readable download name; pod names are DNS-1123
// so they are already header-safe.
func recordingFilename(rec *models.SessionRecording) string {
	return rec.Namespace + "_" + rec.Pod + "_" + rec.StartedAt.UTC().Format("20060102-150405") + ".cast"
}
