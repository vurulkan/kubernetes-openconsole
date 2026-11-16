package api

import (
	"encoding/json"
	"net/http"
	"reflect"

	"k8s-dashboard/backend/internal/problem"
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	emptyItems(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// emptyItems makes a list answer's nil "items" an empty array: Go encodes a nil
// slice as null, which clients read as "not loaded yet" (the detail drawers' events
// spun forever when an object had none, up to 2.23.2).
func emptyItems(payload interface{}) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return
	}
	if v := reflect.ValueOf(m["items"]); v.Kind() == reflect.Slice && v.IsNil() {
		m["items"] = reflect.MakeSlice(v.Type(), 0, 0).Interface()
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
