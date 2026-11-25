package api

import (
	"net/http"
	"slices"
	"strings"

	"k8s-dashboard/backend/internal/kube"
	"k8s-dashboard/backend/internal/problem"
)

// searchLimit caps the ⌘K results; the palette shows them all.
const searchLimit = 30

var searchKindNames = []string{"pods", "deployments", "statefulsets", "daemonsets", "services", "ingresses",
	"configmaps", "jobs", "cronjobs", "hpas", "nodes"}

// handleSearch: ⌘K resource search on the request's cluster, from the informer
// cache only. Only namespace × resource pairs the caller may list (API key scope
// included), never Secrets, nodes only for admins. Not audited: every keystroke
// would be a read (opening a result is audited like any read).
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind != "" && !slices.Contains(searchKindNames, kind) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "kind: one of "+strings.Join(searchKindNames, ", "))
		return
	}
	engine, ok := s.engineForRequest(r)
	if !ok {
		writeError(w, http.StatusForbidden, reasonForbidden)
		return
	}
	query := kube.SearchQuery{Text: q.Get("q"), Kind: kind, Namespace: strings.ToLower(q.Get("ns")), Limit: searchLimit}
	hits := []kube.SearchHit{}
	ic := kubeFor(r).Informers()
	if ic != nil && (len([]rune(strings.TrimSpace(query.Text))) >= 2 || query.Namespace != "") {
		_, query.Nodes = s.isAdminRequest(r)
		cluster := clusterIDFrom(r.Context())
		hits = ic.Search(query, func(ns, resource string) bool {
			return s.featureAllows(resource, "list") && engine.Can(cluster, ns, resource, "list")
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": hits})
}
