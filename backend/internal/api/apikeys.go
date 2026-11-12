package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/kube"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/store"
)

// API keys let a user's agent or script call the API in the user's name. A
// key reaches what it lists ∩ what its owner holds at the time of the call
// (rbac.Engine.WithKey); admin endpoints need the owner to be an admin and
// the key to have the admin scope (isAdminRequest).

const (
	apiKeySecretLen = 40 // base62 characters after "oc_", ~238 bits
	apiKeyPrefixLen = 9  // "oc_" + 6, shown in lists
	// shortcut: fixed per-key rate limit, make it an env var if someone needs another.
	apiKeyRate  = 10
	apiKeyBurst = 30
	// apiKeyTouchEvery thins out last_used_at writes, like session touches.
	apiKeyTouchEvery = 30 * time.Second
	// clusterHeader picks the cluster of an API key request (name or id).
	clusterHeader = "X-OpenConsole-Cluster"
)

const reasonAPIKeyNotAllowed = "api_key_not_allowed"

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// newAPIKeySecret returns a new secret, its display prefix and its SHA-256.
func newAPIKeySecret() (secret, prefix, hash string, err error) {
	b := make([]byte, apiKeySecretLen)
	max := big.NewInt(int64(len(base62)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", "", "", err
		}
		b[i] = base62[n.Int64()]
	}
	secret = auth.APIKeyPrefix + string(b)
	return secret, secret[:apiKeyPrefixLen], hashAPIKey(secret), nil
}

// hashAPIKey: a high-entropy secret needs no slow hash, and a plain digest can be looked up by index.
func hashAPIKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// apiKeyFrom returns the request's API key (nil for a web session).
func apiKeyFrom(ctx context.Context) *models.APIKey {
	if c, ok := auth.FromContext(ctx); ok {
		return c.APIKey
	}
	return nil
}

func apiKeyScopeFrom(ctx context.Context) *models.APIKeyScope {
	if k := apiKeyFrom(ctx); k != nil {
		return &k.APIKeyScope
	}
	return nil
}

// keyAuth is what AuthMiddleware checks API keys with; nil when FEATURE_API_KEYS=false.
func (s *Server) keyAuth() auth.KeyAuthenticator {
	if !featureEnabled(FeatureAPIKeys) {
		return nil
	}
	return s
}

// apiKeyLimits holds the per-key rate limiters and last-use throttles.
type apiKeyLimits struct {
	mu          sync.Mutex
	limiters    map[int]*rate.Limiter
	lastAudit   map[int]time.Time // last rate_limited audit per key
	lastTouched map[int]time.Time
}

func (l *apiKeyLimits) allow(id int) (ok, audit bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limiters == nil {
		l.limiters, l.lastAudit, l.lastTouched = map[int]*rate.Limiter{}, map[int]time.Time{}, map[int]time.Time{}
	}
	lim, found := l.limiters[id]
	if !found {
		lim = rate.NewLimiter(apiKeyRate, apiKeyBurst)
		l.limiters[id] = lim
	}
	if lim.Allow() {
		return true, false
	}
	if time.Since(l.lastAudit[id]) < time.Minute {
		return false, false
	}
	l.lastAudit[id] = time.Now()
	return false, true
}

func (l *apiKeyLimits) dueTouch(id int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.lastTouched[id]) < apiKeyTouchEvery {
		return false
	}
	l.lastTouched[id] = time.Now()
	return true
}

// AuthenticateKey implements auth.KeyAuthenticator. Unlike a session, a key
// is refused when the lookup fails: a minute of errors for an agent is
// cheaper than a door opened to the wrong caller.
func (s *Server) AuthenticateKey(r *http.Request, secret string, keyID int) (*auth.Claims, int) {
	ctx := r.Context()
	var key *models.APIKey
	var err error
	if keyID > 0 {
		key, err = s.store.GetAPIKey(ctx, keyID)
	} else {
		key, err = s.store.GetAPIKeyByHash(ctx, hashAPIKey(secret))
	}
	if errors.Is(err, sql.ErrNoRows) {
		slog.Warn("unknown API key", slog.String("remote_ip", clientIP(r)), slog.String("request_id", logpkg.RequestIDFrom(ctx)))
		return nil, http.StatusUnauthorized
	}
	if err != nil {
		slog.Warn("API key lookup failed; refusing", slog.Any("error", err), slog.String("request_id", logpkg.RequestIDFrom(ctx)))
		return nil, http.StatusUnauthorized
	}
	user, err := s.store.GetUserByID(ctx, key.UserID)
	if err != nil {
		slog.Warn("API key owner lookup failed; refusing", slog.Any("error", err), slog.String("request_id", logpkg.RequestIDFrom(ctx)))
		return nil, http.StatusUnauthorized
	}
	deny := func(outcome, reason string) {
		s.auditEvent(r, models.AuditLog{User: user.Username, AuthSource: user.AuthSource, Verb: audit.VerbUse, Outcome: outcome,
			Reason: reason, ResourceType: audit.KindAPIKey, ResourceName: key.Name, APIKeyID: key.ID, APIKeyName: key.Name})
	}
	switch {
	case key.RevokedAt != nil:
		deny(audit.Denied, "revoked")
		return nil, http.StatusUnauthorized
	case key.ExpiresAt != nil && !time.Now().Before(*key.ExpiresAt):
		deny(audit.Denied, "expired")
		return nil, http.StatusUnauthorized
	case !user.IsActive:
		deny(audit.Denied, "owner_inactive")
		return nil, http.StatusUnauthorized
	case user.MustChangePassword:
		// The key is valid, its owner just cannot use anything yet: 403, not 401.
		deny(audit.Denied, "must_change_password")
		return nil, http.StatusForbidden
	}
	if ok, record := s.keyLimits.allow(key.ID); !ok {
		if record {
			deny(audit.RateLimited, reasonRateLimited)
		}
		return nil, http.StatusTooManyRequests
	}
	if s.keyLimits.dueTouch(key.ID) {
		ip := clientIP(r)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.store.TouchAPIKey(ctx, key.ID, ip)
		}()
	}
	return &auth.Claims{UserID: user.ID, Username: user.Username, APIKey: key}, 0
}

// denyAPIKey refuses, audits and returns true when r carries an API key: a
// key never manages keys, changes the password, picks the cluster or saves views.
func (s *Server) denyAPIKey(w http.ResponseWriter, r *http.Request, e models.AuditLog) bool {
	if apiKeyFrom(r.Context()) == nil {
		return false
	}
	e.Outcome, e.Reason = audit.Denied, reasonAPIKeyNotAllowed
	s.auditEvent(r, e)
	writeError(w, http.StatusForbidden, "not allowed with an API key")
	return true
}

// ─── Ceiling: what the caller may put into a key ────────────────────────────

type ceilingCluster struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type ceilingNamespace struct {
	ClusterID int      `json:"clusterId"`
	Namespace string   `json:"namespace"`
	Grants    []string `json:"grants"` // "pods:list"
}

type keyCeiling struct {
	IsAdmin    bool               `json:"isAdmin"`
	Clusters   []ceilingCluster   `json:"clusters"`
	Namespaces []ceilingNamespace `json:"namespaces"`
	// Disabled are catalog grants the operator switched off (FEATURE_*); no key can hold them.
	Disabled []string `json:"disabled"`
}

// grants returns the ceiling's grants on (cluster, namespace).
func (c keyCeiling) grants(clusterID int, namespace string) []string {
	for _, n := range c.Namespaces {
		if n.ClusterID == clusterID && n.Namespace == namespace {
			return n.Grants
		}
	}
	return nil
}

// pairs expands a scope into the (cluster, namespace) pairs it reaches today.
func (c keyCeiling) pairs(sc models.APIKeyScope) []ceilingNamespace {
	var out []ceilingNamespace
	for _, n := range c.Namespaces {
		if (slices.Contains(sc.Clusters, 0) || slices.Contains(sc.Clusters, n.ClusterID)) &&
			(sc.AllNamespaces || slices.Contains(sc.Namespaces, n.Namespace)) {
			out = append(out, n)
		}
	}
	return out
}

// invalidGrants are the scope's grants the ceiling holds in none of the scope's namespaces.
func (c keyCeiling) invalidGrants(sc models.APIKeyScope) []string {
	pairs := c.pairs(sc)
	out := []string{}
	for _, g := range sc.Grants {
		if !slices.ContainsFunc(pairs, func(p ceilingNamespace) bool { return slices.Contains(p.Grants, g) }) {
			out = append(out, g)
		}
	}
	return out
}

// ceilingFor computes what user may give a key: for an admin every grant in
// every namespace of every reachable cluster, for anyone else their grants.
// It is the web session's view, never narrowed by a key.
func (s *Server) ceilingFor(ctx context.Context, user *models.User) (keyCeiling, error) {
	out := keyCeiling{IsAdmin: user.IsAdmin, Clusters: []ceilingCluster{}, Namespaces: []ceilingNamespace{}, Disabled: []string{}}
	all := []string{}
	for _, c := range rbac.Catalog {
		for _, a := range c.Actions {
			if featureAllows(c.Resource, a) {
				all = append(all, c.Resource+":"+a)
			} else {
				out.Disabled = append(out.Disabled, c.Resource+":"+a)
			}
		}
	}
	clusters, err := s.store.ListClusters(ctx)
	if err != nil {
		return out, err
	}
	var perms []models.NamespacePermission
	if !user.IsAdmin {
		if perms, err = s.store.ListPermissionsByUser(ctx, user.ID); err != nil {
			return out, err
		}
	}
	engine := rbac.New(perms)
	for _, c := range clusters {
		if !user.IsAdmin && !engine.CoversCluster(c.ID) {
			continue
		}
		out.Clusters = append(out.Clusters, ceilingCluster{ID: c.ID, Name: c.Name})
		if user.IsAdmin {
			m, err := s.clusters.Get(ctx, c.ID)
			if err != nil {
				continue // unreachable: no namespaces to offer
			}
			nss, err := s.resources.ListNamespaces(kube.WithManager(ctx, m))
			if err != nil {
				continue
			}
			for _, ns := range nss {
				out.Namespaces = append(out.Namespaces, ceilingNamespace{ClusterID: c.ID, Namespace: ns.Name, Grants: all})
			}
			continue
		}
		byNS := map[string][]string{}
		for _, p := range perms {
			g := strings.ToLower(p.Resource + ":" + p.Action)
			if (p.ClusterID == 0 || p.ClusterID == c.ID) && slices.Contains(all, g) && !slices.Contains(byNS[p.Namespace], g) {
				byNS[p.Namespace] = append(byNS[p.Namespace], g)
			}
		}
		for ns, gs := range byNS {
			out.Namespaces = append(out.Namespaces, ceilingNamespace{ClusterID: c.ID, Namespace: ns, Grants: gs})
		}
	}
	sort.Slice(out.Namespaces, func(i, j int) bool {
		a, b := out.Namespaces[i], out.Namespaces[j]
		return a.ClusterID < b.ClusterID || (a.ClusterID == b.ClusterID && a.Namespace < b.Namespace)
	})
	return out, nil
}

// ─── Handlers (web session only) ─────────────────────────────────────────────

type apiKeyView struct {
	models.APIKey
	// InvalidGrants are grants the owner no longer holds in any of the key's namespaces.
	InvalidGrants []string `json:"invalidGrants"`
}

type apiKeyRequest struct {
	Name          string     `json:"name"`
	Note          string     `json:"note"`
	ExpiresAt     *time.Time `json:"expiresAt"` // create / regenerate; null = no expiry
	AdminScope    bool       `json:"adminScope"`
	Clusters      []int      `json:"clusters"`
	AllNamespaces bool       `json:"allNamespaces"`
	Namespaces    []string   `json:"namespaces"`
	Grants        []string   `json:"grants"`
}

// apiKeyGate runs the checks every key endpoint shares: feature on, web
// session (a key never manages keys) and a usable account.
func (s *Server) apiKeyGate(w http.ResponseWriter, r *http.Request, verb string) (*models.User, bool) {
	e := models.AuditLog{Verb: verb, ResourceType: audit.KindAPIKey, ResourceName: chi.URLParam(r, "id")}
	if !featureEnabled(FeatureAPIKeys) {
		e.Outcome, e.Reason = audit.Denied, reasonFeatureDisabled
		s.auditEvent(r, e)
		writeError(w, http.StatusForbidden, "this feature is disabled by the operator")
		return nil, false
	}
	if s.denyAPIKey(w, r, e) {
		return nil, false
	}
	user, ok := s.userForRequest(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	if user.MustChangePassword {
		writeError(w, http.StatusForbidden, "change your password first")
		return nil, false
	}
	return user, true
}

// ownKey loads the caller's key {id}; another user's key is "not found".
func (s *Server) ownKey(w http.ResponseWriter, r *http.Request, user *models.User) (*models.APIKey, bool) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return nil, false
	}
	k, err := s.store.GetAPIKey(r.Context(), id)
	if err != nil || k.UserID != user.ID {
		writeError(w, http.StatusNotFound, "API key not found")
		return nil, false
	}
	return k, true
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbList)
	if !ok {
		return
	}
	keys, err := s.store.ListAPIKeys(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list API keys")
		return
	}
	ceiling, err := s.ceilingFor(r.Context(), user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read your permissions")
		return
	}
	out := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, apiKeyView{APIKey: k, InvalidGrants: ceiling.invalidGrants(k.APIKeyScope)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleAPIKeyCeiling(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbGet)
	if !ok {
		return
	}
	ceiling, err := s.ceilingFor(r.Context(), user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read your permissions")
		return
	}
	writeJSON(w, http.StatusOK, ceiling)
}

// validateAPIKeyRequest checks req against the caller's ceiling (the trust
// boundary: the UI never offers more, but nothing else stops a crafted request).
func (s *Server) validateAPIKeyRequest(ctx context.Context, user *models.User, req *apiKeyRequest) error {
	req.Name, req.Note = strings.TrimSpace(req.Name), strings.TrimSpace(req.Note)
	switch {
	case req.Name == "" || len(req.Name) > 100:
		return errors.New("name is required (at most 100 characters)")
	case len(req.Note) > 1000:
		return errors.New("note is too long (at most 1000 characters)")
	case req.AdminScope && !user.IsAdmin:
		return errors.New("only admins can give a key the admin scope")
	case len(req.Clusters) == 0:
		return errors.New("pick at least one cluster")
	case !req.AllNamespaces && len(req.Namespaces) == 0:
		return errors.New("pick at least one namespace")
	case len(req.Grants) == 0:
		return errors.New("pick at least one permission")
	}
	ceiling, err := s.ceilingFor(ctx, user)
	if err != nil {
		return err
	}
	if slices.Contains(req.Clusters, 0) {
		req.Clusters = []int{0}
	}
	for _, c := range req.Clusters {
		if c != 0 && !slices.ContainsFunc(ceiling.Clusters, func(x ceilingCluster) bool { return x.ID == c }) {
			return fmt.Errorf("cluster %d is not yours to give", c)
		}
	}
	if req.AllNamespaces {
		req.Namespaces = nil
	}
	sc := models.APIKeyScope{Clusters: req.Clusters, AllNamespaces: req.AllNamespaces}
	for _, ns := range req.Namespaces {
		sc.Namespaces = []string{ns}
		if len(ceiling.pairs(sc)) == 0 {
			return fmt.Errorf("namespace %q is not yours to give on the chosen clusters", ns)
		}
	}
	sc.Namespaces = req.Namespaces
	for i, g := range req.Grants {
		req.Grants[i] = strings.ToLower(strings.TrimSpace(g))
	}
	slices.Sort(req.Grants)
	req.Grants = slices.Compact(req.Grants)
	sc.Grants = req.Grants
	if bad := ceiling.invalidGrants(sc); len(bad) > 0 {
		return fmt.Errorf("permissions you do not hold here: %s", strings.Join(bad, ", "))
	}
	return nil
}

// keySummary is the audit summary of a key's scope (never its secret or hash).
func keySummary(k models.APIKey) string {
	clusters := "all"
	if !slices.Contains(k.Clusters, 0) {
		clusters = strconv.Itoa(len(k.Clusters))
	}
	ns := "all"
	if !k.AllNamespaces {
		ns = strconv.Itoa(len(k.Namespaces))
	}
	return fmt.Sprintf("clusters=%s namespaces=%s grants=%s", clusters, ns, strings.Join(k.Grants, ","))
}

func keyAuditDetails(k models.APIKey) audit.D {
	d := audit.D{"id": k.ID, "summary": keySummary(k), "admin_scope": k.AdminScope}
	if k.ExpiresAt != nil {
		d["expires_at"] = *k.ExpiresAt
	}
	return d
}

func (s *Server) auditAPIKey(r *http.Request, verb, outcome, reason, name string, d audit.D) {
	s.auditEvent(r, models.AuditLog{Verb: verb, Outcome: outcome, Reason: reason, ResourceType: audit.KindAPIKey, ResourceName: name, Details: d})
}

func validExpiry(t *time.Time) bool { return t == nil || t.After(time.Now()) }

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbCreate)
	if !ok {
		return
	}
	var req apiKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !validExpiry(req.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "the expiry must be in the future")
		return
	}
	if err := s.validateAPIKeyRequest(r.Context(), user, &req); err != nil {
		s.auditAPIKey(r, audit.VerbCreate, audit.Denied, "outside_ceiling", req.Name, failDetails(err, nil))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, prefix, hash, err := newAPIKeySecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a key")
		return
	}
	k := models.APIKey{UserID: user.ID, Name: req.Name, Note: req.Note, Prefix: prefix, Hash: hash, AdminScope: req.AdminScope,
		ExpiresAt: req.ExpiresAt, APIKeyScope: models.APIKeyScope{Clusters: req.Clusters, AllNamespaces: req.AllNamespaces,
			Namespaces: req.Namespaces, Grants: req.Grants}}
	if k.ID, err = s.store.CreateAPIKey(r.Context(), k); err != nil {
		if errors.Is(err, store.ErrAPIKeyNameTaken) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.auditAPIKey(r, audit.VerbCreate, audit.Failed, failReason(err), req.Name, failDetails(err, nil))
		writeError(w, http.StatusInternalServerError, "could not save the key")
		return
	}
	s.auditAPIKey(r, audit.VerbCreate, audit.Success, "", k.Name, keyAuditDetails(k))
	created, _ := s.store.GetAPIKey(r.Context(), k.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"key": created, "secret": secret})
}

func (s *Server) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbUpdate)
	if !ok {
		return
	}
	before, ok := s.ownKey(w, r, user)
	if !ok {
		return
	}
	var req apiKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.validateAPIKeyRequest(r.Context(), user, &req); err != nil {
		s.auditAPIKey(r, audit.VerbUpdate, audit.Denied, "outside_ceiling", before.Name, failDetails(err, audit.D{"id": before.ID}))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	k := *before
	k.Name, k.Note, k.AdminScope = req.Name, req.Note, req.AdminScope
	k.APIKeyScope = models.APIKeyScope{Clusters: req.Clusters, AllNamespaces: req.AllNamespaces, Namespaces: req.Namespaces, Grants: req.Grants}
	if err := s.store.UpdateAPIKey(r.Context(), k); err != nil {
		if errors.Is(err, store.ErrAPIKeyNameTaken) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.auditAPIKey(r, audit.VerbUpdate, audit.Failed, failReason(err), before.Name, failDetails(err, audit.D{"id": k.ID}))
		writeError(w, http.StatusInternalServerError, "could not save the key")
		return
	}
	var changed []string
	if k.Name != before.Name {
		changed = append(changed, "name")
	}
	if k.Note != before.Note {
		changed = append(changed, "note")
	}
	if k.AdminScope != before.AdminScope {
		changed = append(changed, "admin_scope")
	}
	if keySummary(k) != keySummary(*before) || !slices.Equal(k.Namespaces, before.Namespaces) || !slices.Equal(k.Clusters, before.Clusters) {
		changed = append(changed, "scope")
	}
	d := keyAuditDetails(k)
	d["changed"] = changed
	s.auditAPIKey(r, audit.VerbUpdate, audit.Success, "", k.Name, d)
	updated, _ := s.store.GetAPIKey(r.Context(), k.ID)
	writeJSON(w, http.StatusOK, map[string]any{"key": updated})
}

func (s *Server) handleRegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbRegenerate)
	if !ok {
		return
	}
	k, ok := s.ownKey(w, r, user)
	if !ok {
		return
	}
	var req struct {
		ExpiresAt *time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validExpiry(req.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "the expiry must be in the future")
		return
	}
	secret, prefix, hash, err := newAPIKeySecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a key")
		return
	}
	if err := s.store.RegenerateAPIKey(r.Context(), k.ID, prefix, hash, req.ExpiresAt); err != nil {
		s.auditAPIKey(r, audit.VerbRegenerate, audit.Failed, failReason(err), k.Name, failDetails(err, audit.D{"id": k.ID}))
		writeError(w, http.StatusInternalServerError, "could not save the key")
		return
	}
	k.ExpiresAt = req.ExpiresAt
	s.auditAPIKey(r, audit.VerbRegenerate, audit.Success, "", k.Name, keyAuditDetails(*k))
	updated, _ := s.store.GetAPIKey(r.Context(), k.ID)
	writeJSON(w, http.StatusOK, map[string]any{"key": updated, "secret": secret})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbRevoke)
	if !ok {
		return
	}
	k, ok := s.ownKey(w, r, user)
	if !ok {
		return
	}
	if err := s.store.RevokeAPIKey(r.Context(), k.ID); err != nil {
		s.auditAPIKey(r, audit.VerbRevoke, audit.Failed, failReason(err), k.Name, failDetails(err, audit.D{"id": k.ID}))
		writeError(w, http.StatusInternalServerError, "could not revoke the key")
		return
	}
	s.auditAPIKey(r, audit.VerbRevoke, audit.Success, "", k.Name, audit.D{"id": k.ID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleDeleteAPIKey removes the key; deleting a live key revokes it too.
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiKeyGate(w, r, audit.VerbDelete)
	if !ok {
		return
	}
	k, ok := s.ownKey(w, r, user)
	if !ok {
		return
	}
	if err := s.store.DeleteAPIKey(r.Context(), k.ID); err != nil {
		s.auditAPIKey(r, audit.VerbDelete, audit.Failed, failReason(err), k.Name, failDetails(err, audit.D{"id": k.ID}))
		writeError(w, http.StatusInternalServerError, "could not delete the key")
		return
	}
	s.auditAPIKey(r, audit.VerbDelete, audit.Success, "", k.Name, audit.D{"id": k.ID})
	w.WriteHeader(http.StatusNoContent)
}
