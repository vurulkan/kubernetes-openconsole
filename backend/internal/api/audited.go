package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/models"
)

// auditNote is what a handler wrapped by adminWrite adds to its audit entry: the
// object's name, where it lives, details, and (for a failure) a reason more
// precise than the answer's code.
type auditNote struct {
	Name      string
	Namespace string
	Cluster   string
	ClusterID int
	Details   audit.D
	Reason    string
}

type auditNoteKey struct{}

// noteFor returns the request's audit note; outside adminWrite it is a throwaway.
func noteFor(r *http.Request) *auditNote {
	if n, ok := r.Context().Value(auditNoteKey{}).(*auditNote); ok {
		return n
	}
	return &auditNote{}
}

// auditedWriter remembers the status and the reason code of the answer.
type auditedWriter struct {
	http.ResponseWriter
	status int
	code   string
}

func (w *auditedWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditedWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *auditedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// noteProblem is called by writeError with the reason code it answers.
func (w *auditedWriter) noteProblem(code string) { w.code = code }

// adminWrite is an admin write endpoint: it refuses a non-admin (403
// admin_only) and writes one audit entry for every answer — success for 2xx,
// denied for the refusal, failed (with the answer's reason code) otherwise —
// so a new error path can't forget its entry. The handler only adds the name
// and details through noteFor(r).
func (s *Server) adminWrite(verb, kind string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		note := &auditNote{}
		aw := &auditedWriter{ResponseWriter: w}
		outcome, reason := audit.Success, ""
		if _, ok := s.isAdminRequest(r); !ok {
			writeError(aw, http.StatusForbidden, reasonAdminOnly)
			outcome, reason = audit.Denied, reasonAdminOnly
		} else {
			h(aw, r.WithContext(context.WithValue(r.Context(), auditNoteKey{}, note)))
			if aw.status >= 400 {
				outcome, reason = audit.Failed, aw.code
				if note.Reason != "" {
					reason = note.Reason
				}
			}
		}
		name := note.Name
		if name == "" && chi.URLParam(r, "id") != "" {
			name = "id:" + chi.URLParam(r, "id")
		}
		if name == "" {
			name = "*"
		}
		s.auditEvent(r, models.AuditLog{Verb: verb, ResourceType: kind, Outcome: outcome, Reason: reason,
			ResourceName: name, Namespace: note.Namespace, Cluster: note.Cluster, ClusterID: note.ClusterID, Details: note.Details})
	}
}
