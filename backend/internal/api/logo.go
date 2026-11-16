package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

const (
	logoFileName     = "custom_logo"
	logoMetaFileName = "custom_logo.meta"
	maxLogoSize      = 5 << 20
)

func (s *Server) logoPath() string {
	return filepath.Join(s.dataDir, logoFileName)
}

func (s *Server) logoMetaPath() string {
	return filepath.Join(s.dataDir, logoMetaFileName)
}

func (s *Server) handleGetLogo(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.logoPath())
	if err != nil {
		writeError(w, http.StatusNotFound, problem.NotFound)
		return
	}
	contentType := http.DetectContentType(data)
	if meta, err := os.ReadFile(s.logoMetaPath()); err == nil && len(meta) > 0 {
		contentType = strings.TrimSpace(string(meta))
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxLogoSize); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "invalid upload")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "missing file")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxLogoSize+1))
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to read file")
		return
	}
	if len(data) == 0 || len(data) > maxLogoSize {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "invalid file size")
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	contentType := http.DetectContentType(data)
	if ext == ".svg" {
		contentType = "image/svg+xml"
	}
	if !strings.HasPrefix(contentType, "image/") {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "unsupported file type")
		return
	}

	if err := os.WriteFile(s.logoPath(), data, 0o600); err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to store logo")
		return
	}
	_ = os.WriteFile(s.logoMetaPath(), []byte(contentType), 0o600)
	s.recordSettingsUpdate(r, "logo", audit.D{"size_bytes": len(data)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteLogo(w http.ResponseWriter, r *http.Request) {
	_ = os.Remove(s.logoPath())
	_ = os.Remove(s.logoMetaPath())
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindSettings, ResourceName: "logo"})
	w.WriteHeader(http.StatusNoContent)
}
