package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	logpkg "k8s-dashboard/backend/internal/logging"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/store"

	"github.com/go-ldap/ldap/v3"
)

// sessionValidator is the AuthMiddleware adapter around *store.Store. Returning
// (false, nil) from Validate rejects a token; errors propagate so middleware
// can fail-open on a DB blip. Pre-tracking JWTs (no jti) never reach Validate
// — middleware shortcuts them in.
type sessionValidator struct {
	s *store.Store
	t *store.SessionToucher
}

func (v *sessionValidator) Validate(ctx context.Context, jti string) (bool, error) {
	status, err := v.s.LookupSession(ctx, jti)
	if err != nil {
		return false, err
	}
	// Row missing = JWT issued before session tracking existed. Honor it
	// until it expires naturally so the deployment doesn't log everyone out.
	if !status.Found {
		return true, nil
	}
	if status.Revoked || status.Expired {
		return false, nil
	}
	return true, nil
}

func (v *sessionValidator) Touch(jti string, until time.Time) { v.t.Touch(jti, until) }

// authValidator wires the Store + toucher into the shape AuthMiddleware wants.
// Returned fresh each time so AuthMiddleware never holds a reference it could
// outlive — in practice the Server lifetime is the process lifetime, so this
// is cosmetic.
func (s *Server) authValidator() auth.SessionValidator {
	return &sessionValidator{s: s.store, t: s.sessionToucher}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Username) > maxUsernameLen {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}

	gateKeys := loginGateKeys(clientIP(r), request.Username)
	if ok, retry := LoginGate().check(gateKeys); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		s.recordLoginAudit(r, request.Username, audit.Locked, "too_many_failures", nil)
		writeError(w, http.StatusTooManyRequests, problem.RateLimited)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), request.Username)
	// No account yet: with LDAP auto-provisioning on, a directory user gets
	// one on their first sign-in. (A disabled account is found above and is
	// never re-created.)
	directoryChecked := false
	if errors.Is(err, sql.ErrNoRows) {
		if provisioned, ok := s.ldapAutoProvision(r, request.Username, request.Password); ok {
			user, err, directoryChecked = provisioned, nil, true
		}
	}
	if err != nil || !user.IsActive {
		LoginGate().recordFailure(gateKeys)
		s.recordLoginAudit(r, request.Username, audit.Failed, "unknown_user", nil)
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}

	// The account's source decides how the password is checked. Directory
	// and Azure AD accounts never accept a local password, even if one was
	// stored before 2.13 (an old reset), so they can't bypass the directory;
	// a local account never accepts a directory password, so a directory
	// entry with the same name can't take it over (built-in admin included).
	method := ""
	failReason := "bad_password"
	if directoryChecked {
		method = models.AuthSourceLDAP
	} else {
		switch user.AuthSource {
		case models.AuthSourceAzure:
			failReason = "azure_account"
		case models.AuthSourceLDAP:
			if s.ldapAuthenticate(r.Context(), request.Username, request.Password) {
				method = models.AuthSourceLDAP
			}
		default:
			if auth.ComparePassword(user.PasswordHash, request.Password) == nil {
				method = models.AuthSourceLocal
			}
		}
	}

	if method == "" {
		LoginGate().recordFailure(gateKeys)
		s.recordLoginAudit(r, request.Username, audit.Failed, failReason, audit.D{"account_source": user.AuthSource})
		// Same answer for every failure, so the response doesn't reveal
		// whether an account exists or where it signs in.
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}

	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	// Two-factor sign-in: the password alone starts no session, only the
	// code step (and the login gate is cleared only once the code is right).
	if models.TwoFactorOn(settings.TwoFactorPolicy) && user.TwoFactorEnabled {
		writeJSON(w, http.StatusOK, map[string]string{"twoFactor": "verify", "challenge": auth.IssueChallenge(user.ID)})
		return
	}
	s.finishLogin(w, r, user, gateKeys, audit.D{"login_method": method},
		models.TwoFactorRequired(settings.TwoFactorPolicy, user) && !user.TwoFactorEnabled, nil)
}

// finishLogin starts the session of a completed sign-in (password, and the
// code when asked). enroll: the policy requires two-factor sign-in the user
// hasn't set up, so the session can only set it up. extra goes into the answer.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, user *models.User, gateKeys []gateKey, login audit.D, enroll bool, extra map[string]any) {
	_ = s.store.MarkLogin(r.Context(), user.ID)
	s.recordLoginAudit(r, user.Username, audit.Success, "", login)
	LoginGate().recordSuccess(gateKeys)
	token, err := s.newSession(r, user, enroll)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	out := map[string]any{"token": token, "user": user}
	for k, v := range extra {
		out[k] = v
	}
	if enroll {
		out["twoFactor"] = "enroll"
	}
	writeJSON(w, http.StatusOK, out)
}

// ldapAutoProvision handles a sign-in by someone who has no account yet.
// With "create accounts on first sign-in" enabled in the LDAP settings, the
// password is checked against the directory and, if it is right, an LDAP
// account is created under the name the directory uses, in the configured
// groups. If an LDAP account already exists under that name (the user typed
// "John" for "john") it is returned instead. ok is false when the setting is
// off or the directory refuses the credentials.
func (s *Server) ldapAutoProvision(r *http.Request, typed, password string) (*models.User, bool) {
	ctx := r.Context()
	cfg, err := s.store.GetLDAPConfig(ctx)
	if err != nil || !cfg.Enabled || !cfg.AutoProvision || strings.TrimSpace(typed) == "" {
		return nil, false
	}
	name, err := auth.LDAPAuthenticateUser(ldapAuthConfig(cfg), typed, password)
	if err != nil {
		logLDAPFailure(ctx, typed, err)
		return nil, false
	}
	name = strings.TrimSpace(name)
	if existing, err := s.store.GetUserByUsername(ctx, name); err == nil {
		if existing.AuthSource == models.AuthSourceLDAP && existing.IsActive {
			return existing, true
		}
		return nil, false
	}
	hash, err := auth.HashPassword(randomPassword())
	if err != nil {
		return nil, false
	}
	groups := s.existingGroupIDs(ctx, cfg.AutoProvisionGroupIDs)
	id, err := s.store.CreateDirectoryUser(ctx, name, hash, models.AuthSourceLDAP, groups)
	if err != nil {
		// Lost a race with a parallel first sign-in: use that account.
		if existing, getErr := s.store.GetUserByUsername(ctx, name); getErr == nil && existing.AuthSource == models.AuthSourceLDAP {
			return existing, true
		}
		slog.Error("LDAP account creation failed", slog.String("user", name), slog.Any("error", err))
		return nil, false
	}
	user, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, false
	}
	s.auditEvent(r, models.AuditLog{
		User:         name,
		Verb:         audit.VerbCreate,
		ResourceType: audit.KindUser,
		ResourceName: name,
		AuthSource:   models.AuthSourceLDAP,
		Details:      audit.D{"account_source": models.AuthSourceLDAP, "groups": len(groups), "auto_provisioned": true},
	})
	return user, true
}

// existingGroupIDs drops ids of groups that no longer exist.
func (s *Server) existingGroupIDs(ctx context.Context, ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil
	}
	known := map[int]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	out := []int{}
	for _, id := range ids {
		if known[id] {
			out = append(out, id)
		}
	}
	return out
}

// ldapAuthenticate binds as the user against the configured directory; false
// when LDAP is off, unconfigured or the credentials are wrong.
// ldapAuthConfig is the stored LDAP settings as the auth package takes them.
func ldapAuthConfig(cfg models.LDAPConfig) auth.LDAPConfig {
	return auth.LDAPConfig{
		Enabled:           cfg.Enabled,
		URL:               cfg.URL,
		Host:              cfg.Host,
		Port:              cfg.Port,
		UseSSL:            cfg.UseSSL,
		StartTLS:          cfg.StartTLS,
		SkipVerify:        cfg.SkipVerify,
		CACert:            cfg.CACert,
		TimeoutSeconds:    cfg.TimeoutSeconds,
		BindDN:            cfg.BindDN,
		BindPassword:      cfg.BindPassword,
		UserBaseDN:        cfg.UserBaseDN,
		UserBaseDNs:       cfg.UserBaseDNs,
		UserFilter:        cfg.UserFilter,
		UsernameAttribute: cfg.UsernameAttribute,
	}
}

func (s *Server) ldapAuthenticate(ctx context.Context, username, password string) bool {
	cfg, err := s.store.GetLDAPConfig(ctx)
	if err != nil || !cfg.Enabled {
		return false
	}
	if err := auth.LDAPAuthenticate(ldapAuthConfig(cfg), username, password); err != nil {
		logLDAPFailure(ctx, username, err)
		return false
	}
	return true
}

// logLDAPFailure logs why a directory sign-in failed. The audit entry only says
// bad_password; the directory's answer is what an operator needs (unreachable,
// TLS, bind DN, base DN, filter). A wrong password is info, the rest a warning.
func logLDAPFailure(ctx context.Context, username string, err error) {
	level := slog.LevelWarn
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		level = slog.LevelInfo
	}
	slog.Log(ctx, level, "ldap sign-in failed", slog.String("user", username),
		slog.String("error", err.Error()), slog.String("request_id", logpkg.RequestIDFrom(ctx)))
}

// sessionMaxAge is how long a session lasts however active it is (or the
// inactivity timeout, when an admin set that longer); then sign in again.
const sessionMaxAge = 12 * time.Hour

// newSession signs a session token for user and records it. The session ends
// after the inactivity timeout (Admin → session setting, minutes) without
// activity, which TouchSession moves on, and at the latest after
// sessionMaxAge (the JWT's own expiry).
func (s *Server) newSession(r *http.Request, user *models.User, enroll bool) (string, error) {
	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		return "", err
	}
	idle := time.Duration(settings.SessionMinutes) * time.Minute
	jti, err := newSessionID()
	if err != nil {
		return "", err
	}
	token, err := auth.GenerateSessionToken(s.jwtKey, user.ID, user.Username, jti, max(sessionMaxAge, idle), idle, enroll)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	// Session row failure is logged but doesn't fail the login — the JWT is
	// still valid; the admin loses revocation visibility for this session
	// until the next login, which is the desired safety trade-off.
	if err := s.store.CreateSession(r.Context(), jti, user.ID, now, now.Add(idle), clientIP(r), r.UserAgent()); err != nil {
		slog.Warn("could not record session", "user", user.Username, "error", err.Error())
	}
	return token, nil
}

// newSessionID returns a URL-safe 128-bit random string used as the JWT jti
// claim and the primary key in session_tokens. 128 bits of entropy is enough
// that we never need to worry about jti collisions.
func newSessionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func (s *Server) handleAuthProviders(w http.ResponseWriter, r *http.Request) {
	azureEnabled := false
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err == nil && cfg.Enabled && cfg.ClientID != "" && cfg.TenantID != "" && cfg.RedirectURL != "" {
		azureEnabled = true
	}
	writeJSON(w, http.StatusOK, map[string]bool{"azureAdEnabled": azureEnabled})
}

func (s *Server) handleAzureStart(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil || !cfg.Enabled || cfg.ClientID == "" || cfg.TenantID == "" || cfg.RedirectURL == "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.NotConfigured, "azure ad is not configured")
		return
	}
	state := randomPassword()
	http.SetCookie(w, &http.Cookie{
		Name:     "azure_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	url, err := auth.AzureAuthorizeURL(ctx, auth.AzureADConfig{
		Authority:    s.azureAuthority,
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}, state)
	if err != nil {
		writeErrorDetail(w, http.StatusBadGateway, problem.SignInFailed, "failed to initialize azure login")
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// checkAzureOwner binds user to the Entra object oid on its first Azure AD
// sign-in and returns "" when oid may use the account, else the audit reason.
func (s *Server) checkAzureOwner(r *http.Request, user *models.User, oid string) string {
	if user.AuthSource != models.AuthSourceAzure {
		return "not_azure_account"
	}
	if bound, err := s.store.BindUserAzureOID(r.Context(), user.ID, oid); err != nil || bound != oid {
		return "azure_oid_mismatch"
	}
	return ""
}

func (s *Server) handleAzureCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("azure_oauth_state")
	if err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.SignInFailed, "missing oauth state")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "azure_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	if r.URL.Query().Get("state") == "" || stateCookie.Value != r.URL.Query().Get("state") {
		writeErrorDetail(w, http.StatusBadRequest, problem.SignInFailed, "invalid oauth state")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.SignInFailed, "missing oauth code")
		return
	}
	cfg, err := s.store.GetAzureADConfig(r.Context())
	if err != nil || !cfg.Enabled {
		writeErrorDetail(w, http.StatusBadRequest, problem.NotConfigured, "azure ad is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	identity, err := auth.AzureExchangeCode(ctx, auth.AzureADConfig{
		Authority:    s.azureAuthority,
		Enabled:      cfg.Enabled,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
	}, code)
	if err != nil {
		writeErrorDetail(w, http.StatusUnauthorized, problem.SignInFailed, "azure authentication failed")
		return
	}

	username := identity.Username
	// Accounts are bound to the Entra object id; without one, nobody is
	// signed in (and no account is created).
	if identity.OID == "" {
		s.recordLoginAudit(r, username, audit.Failed, "azure_no_oid", audit.D{"login_method": models.AuthSourceAzure})
		writeErrorDetail(w, http.StatusForbidden, problem.SignInFailed, "this account can't sign in with this Microsoft account")
		return
	}
	// Microsoft did the second factor, or the sign-in is refused (before any
	// account is created). v2.0 tokens carry amr only when the app
	// registration asks for the optional claim.
	if cfg.RequireMFA && !slices.Contains(identity.AMR, "mfa") {
		if len(identity.AMR) == 0 {
			slog.Warn("azure ad sign-in refused: the id_token has no amr claim; add the optional claim amr (ID token) to the app registration",
				slog.String("user", username), slog.String("request_id", logpkg.RequestIDFrom(r.Context())))
		}
		s.recordLoginAudit(r, username, audit.Denied, problem.AzureMFARequired, audit.D{"login_method": models.AuthSourceAzure})
		http.Redirect(w, r, "/login?error="+problem.AzureMFARequired, http.StatusFound)
		return
	}
	linkedBy := ""
	user, err := s.store.GetUserByUsername(r.Context(), username)
	if errors.Is(err, sql.ErrNoRows) {
		// An admin may have pre-created the account under the person's
		// e-mail or UPN (or in another letter case). Only Azure AD accounts
		// nobody has signed in to yet can be claimed this way, so this can
		// never take over a local, LDAP or already used account.
		for _, candidate := range []struct{ name, via string }{
			{username, "username_case"}, {identity.Email, "email"}, {identity.UPN, "upn"},
		} {
			if candidate.name == "" {
				continue
			}
			if found, findErr := s.store.FindUnclaimedAzureAccount(r.Context(), candidate.name); findErr == nil {
				user, err, linkedBy = found, nil, candidate.via
				break
			}
		}
	}
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load user")
			return
		}
		randomHash, hashErr := auth.HashPassword(randomPassword())
		if hashErr != nil {
			writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to initialize user")
			return
		}
		userID, createErr := s.store.CreateUser(r.Context(), username, randomHash)
		if createErr != nil {
			writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to create user")
			return
		}
		_ = s.store.SetUserAuthSource(r.Context(), userID, models.AuthSourceAzure)
		user, err = s.store.GetUserByID(r.Context(), userID)
		if err != nil {
			writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to load user")
			return
		}
	}
	if !user.IsActive {
		writeErrorDetail(w, http.StatusForbidden, problem.SignInFailed, "user is disabled")
		return
	}
	// Only an Azure AD account signs in here: a local or LDAP account with the
	// same name is never taken over. The account belongs to the Entra object
	// (oid) that first signs in to it; another object with the same name
	// (a renamed or re-created user) is refused.
	if reason := s.checkAzureOwner(r, user, identity.OID); reason != "" {
		s.recordLoginAudit(r, username, audit.Failed, reason,
			audit.D{"login_method": models.AuthSourceAzure, "account_source": user.AuthSource})
		writeErrorDetail(w, http.StatusForbidden, problem.SignInFailed, "this account can't sign in with this Microsoft account")
		return
	}
	_ = s.store.MarkLogin(r.Context(), user.ID)

	token, err := s.newSession(r, user, false)
	if err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to start the session")
		return
	}
	login := audit.D{"login_method": models.AuthSourceAzure}
	if linkedBy != "" {
		login["linked_by"] = linkedBy
		login["signed_in_as"] = username
	}
	s.recordLoginAudit(r, user.Username, audit.Success, "", login)

	// The global securityHeaders middleware blocks inline scripts with CSP
	// script-src 'self'. This bootstrap page writes the token into
	// localStorage before redirecting, so we have to permit THIS inline
	// script. Give it a per-response nonce and override CSP for this
	// response only — same middleware check lets handler-set headers win.
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		writeErrorDetail(w, http.StatusInternalServerError, problem.InternalError, "failed to generate nonce")
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes[:])
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonce+"'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"font-src 'self' data:; "+
			"img-src 'self' data: blob:; "+
			"connect-src 'self' ws: wss:; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fmt.Sprintf(`<!doctype html><html><body><script nonce=%q>
try { localStorage.setItem('authToken', %q); } catch (e) {}
window.location.replace('/overview'); // admins land on the overview, the route sends others to the dashboard
</script></body></html>`, nonce, token)))
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	perms, err := s.store.ListPermissionsByUser(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	out := map[string]interface{}{"user": user}
	if k := apiKeyFrom(r.Context()); k != nil {
		// With a key: what the key reaches now, and the key itself (never its secret).
		perms = rbac.Restrict(perms, &k.APIKeyScope)
		out["apiKey"] = k
	}
	out["namespaces"] = rbac.New(perms).AllowedNamespaces(clusterIDFrom(r.Context()))
	out["twoFactor"] = s.twoFactorStatus(r, user)
	out["permissions"] = perms
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userForRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	if s.denyAPIKey(w, r, models.AuditLog{Verb: audit.VerbChangePassword, ResourceType: audit.KindUser, ResourceName: user.Username}) {
		return
	}
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	if err := auth.ComparePassword(user.PasswordHash, request.CurrentPassword); err != nil {
		// Not 401: the session is fine, and the UI signs out on 401.
		writeError(w, http.StatusBadRequest, problem.WrongPassword)
		return
	}
	if err := auth.CheckPasswordPolicy(request.NewPassword, s.passwordMinLength); err != nil {
		writeErrorDetail(w, http.StatusBadRequest, problem.WeakPassword, err.Error())
		return
	}
	if request.NewPassword == request.CurrentPassword {
		writeError(w, http.StatusBadRequest, problem.PasswordUnchanged)
		return
	}
	hash, err := auth.HashPassword(request.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), user.ID, hash, false); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	// Password change invalidates every session this user holds — including
	// the one that made this call. The browser then falls back to the login
	// screen on its next request, which is the intended UX.
	if err := s.store.RevokeAllForUser(r.Context(), user.ID); err != nil {
		slog.Warn("could not revoke sessions after password change", "user", user.Username, "error", err.Error())
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbChangePassword, ResourceType: audit.KindUser, ResourceName: user.Username})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
