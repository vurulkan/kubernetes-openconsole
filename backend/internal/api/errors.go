package api

import (
	"encoding/json"
	"net/http"

	"k8s-dashboard/backend/internal/problem"
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// writeError answers an error as problem details (see package problem): code is
// one of problem's constants, never free text.
func writeError(w http.ResponseWriter, status int, code string) {
	writeErrorDetail(w, status, code, "")
}

// writeErrorDetail is writeError with an English detail for a human: which
// field, which name. Clients switch on the code, never on the detail.
func writeErrorDetail(w http.ResponseWriter, status int, code, detail string) {
	if n, ok := w.(interface{ noteProblem(string) }); ok {
		n.noteProblem(code) // adminWrite audits it as the reason
	}
	problem.Write(w, status, code, detail)
}
