package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/audit"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
	"k8s-dashboard/backend/internal/store"
)

type facetsEntry struct {
	at     time.Time
	facets store.AuditFacets
}

const (
	auditListMax   = 500    // rows per Audit Logs page
	auditExportMax = 50_000 // rows per CSV export, newest first
)

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	if limit < 1 || limit > auditListMax {
		limit = auditListMax
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			offset = parsed
		}
	}
	filter, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	logs, err := s.store.ListAuditLogsFiltered(r.Context(), limit, offset, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	total, err := s.store.CountAuditLogsFiltered(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	type auditItem struct {
		models.AuditLog
		TimestampFormatted string `json:"timestampFormatted"`
	}
	formatted := make([]auditItem, 0, len(logs))
	for _, entry := range logs {
		formatted = append(formatted, auditItem{entry, entry.Timestamp.In(s.timezone).Format("2006-01-02 15:04:05")})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":    formatted,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"timezone": s.timezone.String(),
	})
}

// auditFilterFrom reads the audit filter query parameters: user, action
// (contains; "family.*" for a whole family; a trailing outcome as in
// deployment.restart.success is split off), actionExact=1, verb, outcome,
// resourceType, resourceName, cluster, namespace, start, end.
func auditFilterFrom(w http.ResponseWriter, r *http.Request) (store.AuditFilter, bool) {
	q := r.URL.Query()
	f := store.AuditFilter{
		User:         q.Get("user"),
		Action:       q.Get("action"),
		ActionExact:  q.Get("actionExact") == "1" || q.Get("actionExact") == "true",
		Verb:         q.Get("verb"),
		Outcome:      q.Get("outcome"),
		ResourceType: q.Get("resourceType"),
		ResourceName: q.Get("resourceName"),
		Cluster:      q.Get("cluster"),
		Namespace:    q.Get("namespace"),
		Source:       q.Get("source"), // web | api_key
		APIKey:       q.Get("apiKey"),
		Start:        parseTimeParam(q.Get("start")),
		End:          parseTimeParam(q.Get("end")),
	}
	if f.Outcome != "" && !slices.Contains(audit.Outcomes, f.Outcome) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "outcome must be one of "+strings.Join(audit.Outcomes, ", "))
		return f, false
	}
	if f.Verb != "" && !slices.Contains(audit.Verbs, f.Verb) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "unknown verb")
		return f, false
	}
	return f, true
}

// handleAuditFacets lists the actions, users and namespaces found in the
// audit log, for the filter suggestions in Admin → Audit Logs.
func (s *Server) handleAuditFacets(w http.ResponseWriter, r *http.Request) {
	if e := s.facets.Load(); e != nil && time.Since(e.at) < time.Minute {
		writeJSON(w, http.StatusOK, e.facets)
		return
	}
	facets, err := s.store.AuditFacets(r.Context(), 1000)
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to read audit facets")
		return
	}
	s.facets.Store(&facetsEntry{at: time.Now(), facets: facets})
	writeJSON(w, http.StatusOK, facets)
}

// handleAuditLogsExport streams the matching entries as CSV, newest first, at
// most auditExportMax (or ?limit=). Rows are written as they are read.
func (s *Server) handleAuditLogsExport(w http.ResponseWriter, r *http.Request) {
	filter, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	limit := auditExportMax
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed < limit {
			limit = parsed
		}
	}
	extendWriteDeadline(w, 10*time.Minute)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-logs.csv")
	writer := newCSVWriter(w)
	_ = writer.Write([]string{"timestamp", "user", "action", "verb", "outcome", "reason", "cluster", "namespace",
		"resource_type", "resource_name", "details", "source_ip", "user_agent", "auth_source", "request_id", "api_key_name"})
	err := s.store.EachAuditLog(r.Context(), limit, filter, func(entry models.AuditLog) error {
		details := ""
		if len(entry.Details) > 0 {
			b, _ := json.Marshal(entry.Details)
			details = string(b)
		}
		return writer.Write([]string{
			entry.Timestamp.In(s.timezone).Format(time.RFC3339),
			entry.User,
			entry.Action,
			entry.Verb,
			entry.Outcome,
			entry.Reason,
			entry.Cluster,
			entry.Namespace,
			entry.ResourceType,
			entry.ResourceName,
			details,
			entry.SourceIP,
			entry.UserAgent,
			entry.AuthSource,
			entry.RequestID,
			entry.APIKeyName,
		})
	})
	writer.Flush()
	if err != nil {
		// Headers are gone; the file just ends early. The log says why.
		slog.Warn("audit export stopped", slog.Any("error", err), slog.String("request_id", logpkg.RequestIDFrom(r.Context())))
	}
}

func parseTimeParam(value string) *time.Time {
	if value == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return &parsed
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return &parsed
	}
	return nil
}
