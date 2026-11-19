package api

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"rsc.io/qr"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
)

// Two-factor sign-in (TOTP) for local and LDAP accounts. The code, the secret
// and the recovery codes never go into audit or logs.

const recoveryCodeCount = 10

// authn is the sign-in check of every authenticated route: the session or API
// key (auth.AuthMiddleware), then the two-factor enrollment gate.
func (s *Server) authn() func(http.Handler) http.Handler {
	check := auth.AuthMiddleware(s.jwtKey, s.authValidator(), s.keyAuth())
	return func(next http.Handler) http.Handler { return check(enrollGate(next)) }
}

// enrollAllowed is what a session that must still set up two-factor sign-in
// may call: who am I, change the password (that comes first), set it up.
var enrollAllowed = map[string]bool{
	"GET /api/auth/me":               true,
	"POST /api/auth/change-password": true,
	"POST /api/me/2fa/setup":         true,
	"POST /api/me/2fa/confirm":       true,
}

func enrollGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := auth.FromContext(r.Context()); ok && c.Enroll && !enrollAllowed[r.Method+" "+r.URL.Path] {
			writeError(w, http.StatusForbidden, problem.TwoFactorEnrollmentRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// twoFactorStatus is the account's two-factor state for /api/auth/me.
func (s *Server) twoFactorStatus(r *http.Request, user *models.User) map[string]any {
	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		return nil
	}
	out := map[string]any{
		"policy":   settings.TwoFactorPolicy,
		"enabled":  user.TwoFactorEnabled,
		"required": models.TwoFactorRequired(settings.TwoFactorPolicy, user),
		"enroll":   false,
	}
	if c, ok := auth.FromContext(r.Context()); ok {
		out["enroll"] = c.Enroll
	}
	if user.TwoFactorEnabled {
		if n, err := s.store.RecoveryCodesLeft(r.Context(), user.ID); err == nil {
			out["recoveryCodesLeft"] = n
		}
	}
	return out
}

// twoFactorCaller is the signed-in user of a /api/me/2fa call: a web session
// (never an API key), a local or LDAP account, the policy not off.
func (s *Server) twoFactorCaller(w http.ResponseWriter, r *http.Request, verb string) (*models.User, string, bool) {
	user, ok := s.userForRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return nil, "", false
	}
	if s.denyAPIKey(w, r, models.AuditLog{Verb: verb, ResourceType: audit.KindTwoFactor, ResourceName: user.Username}) {
		return nil, "", false
	}
	settings, err := s.store.GetSessionSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return nil, "", false
	}
	if !models.TwoFactorOn(settings.TwoFactorPolicy) || user.AuthSource == models.AuthSourceAzure {
		writeError(w, http.StatusConflict, problem.TwoFactorOff)
		return nil, "", false
	}
	return user, settings.TwoFactorPolicy, true
}

// readCode reads {"code": "…"} (and the challenge of the sign-in step).
func readCode(w http.ResponseWriter, r *http.Request) (code, challenge string, ok bool) {
	var body struct {
		Code      string `json:"code"`
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Code) > 64 {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return "", "", false
	}
	return body.Code, body.Challenge, true
}

// checkCode accepts a TOTP code from the app or, with recovery, an unused
// recovery code (which it spends). It returns the method used, "" when neither.
func (s *Server) checkCode(r *http.Request, user *models.User, code string, recovery bool) (string, error) {
	tf, err := s.store.GetTwoFactor(r.Context(), user.ID)
	if err != nil || !tf.Enabled {
		return "", err
	}
	if step, ok := auth.CheckTOTP(tf.Secret, code, tf.LastStep, time.Now()); ok {
		if used, err := s.store.UseTOTPStep(r.Context(), user.ID, step); err != nil || !used {
			return "", err
		}
		return "totp", nil
	}
	if !recovery {
		return "", nil
	}
	if used, err := s.store.UseRecoveryCode(r.Context(), user.ID, auth.HashRecoveryCode(code)); err != nil || !used {
		return "", err
	}
	return "recovery_code", nil
}

// handleTwoFactorVerify is the code step of a sign-in: challenge + code → session.
func (s *Server) handleTwoFactorVerify(w http.ResponseWriter, r *http.Request) {
	code, challenge, ok := readCode(w, r)
	if !ok {
		return
	}
	userID, ok := auth.PeekChallenge(challenge)
	if !ok {
		writeError(w, http.StatusUnauthorized, problem.TwoFactorChallengeExpired)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil || !user.IsActive {
		auth.EndChallenge(challenge)
		writeError(w, http.StatusUnauthorized, problem.Unauthorized)
		return
	}
	entry := models.AuditLog{User: user.Username, Verb: audit.VerbVerify, ResourceType: audit.KindTwoFactor,
		ResourceName: user.Username, AuthSource: user.AuthSource}
	gateKeys := loginGateKeys(clientIP(r), user.Username)
	if ok, retry := LoginGate().check(gateKeys); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		entry.Outcome, entry.Reason = audit.Locked, "too_many_failures"
		s.auditEvent(r, entry)
		writeError(w, http.StatusTooManyRequests, problem.RateLimited)
		return
	}
	method, err := s.checkCode(r, user, code, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if method == "" {
		// The same counters as a wrong password: 5 per address, 20 per account.
		LoginGate().recordFailure(gateKeys)
		entry.Outcome, entry.Reason = audit.Failed, "invalid_code"
		s.auditEvent(r, entry)
		writeError(w, http.StatusUnauthorized, problem.TwoFactorInvalid)
		return
	}
	auth.EndChallenge(challenge)
	entry.Details = audit.D{"two_factor_method": method}
	var extra map[string]any
	if method == "recovery_code" {
		left, _ := s.store.RecoveryCodesLeft(r.Context(), user.ID)
		entry.Details["recovery_codes_left"] = left
		extra = map[string]any{"recoveryCodesLeft": left}
	}
	s.auditEvent(r, entry)
	s.finishLogin(w, r, user, gateKeys, audit.D{"login_method": user.AuthSource, "two_factor_method": method}, false, extra)
}

// handleTwoFactorSetup starts setting up: a new secret, not on until confirmed.
func (s *Server) handleTwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.twoFactorCaller(w, r, audit.VerbEnable)
	if !ok {
		return
	}
	if user.TwoFactorEnabled {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, "two-factor sign-in is on already; turn it off first")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err == nil {
		err = s.store.SetPendingTOTP(r.Context(), user.ID, secret)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	// The host tells two consoles (test, production) apart in the app.
	uri := auth.TOTPURI("OpenConsole", user.Username+"@"+r.Host, secret)
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	code.Scale = 6
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    uri,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()),
	})
}

// handleTwoFactorConfirm turns it on with a code from the app, returns the
// recovery codes once, and starts a new session (every other one ends).
func (s *Server) handleTwoFactorConfirm(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.twoFactorCaller(w, r, audit.VerbEnable)
	if !ok {
		return
	}
	code, _, ok := readCode(w, r)
	if !ok {
		return
	}
	entry := models.AuditLog{Verb: audit.VerbEnable, ResourceType: audit.KindTwoFactor, ResourceName: user.Username}
	if user.TwoFactorEnabled {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, "two-factor sign-in is on already")
		return
	}
	tf, err := s.store.GetTwoFactor(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	step, valid := auth.CheckTOTP(tf.Secret, code, 0, time.Now())
	if tf.Secret == "" || !valid {
		entry.Outcome, entry.Reason = audit.Failed, "invalid_code"
		s.auditEvent(r, entry)
		// 400, not 401: the session is fine (the UI signs out on 401).
		writeError(w, http.StatusBadRequest, problem.TwoFactorInvalid)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err == nil {
		err = s.store.EnableTOTP(r.Context(), user.ID, step, hashes)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if err := s.store.RevokeAllForUser(r.Context(), user.ID); err != nil {
		slog.Warn("could not end sessions after two-factor set-up", "user", user.Username, "error", err.Error())
	}
	s.auditEvent(r, entry)
	user.TwoFactorEnabled = true
	token, err := s.newSession(r, user, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "token": token, "user": user})
}

// handleTwoFactorRecoveryCodes replaces the recovery codes (a code from the app proves it's the owner).
func (s *Server) handleTwoFactorRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.twoFactorCaller(w, r, audit.VerbRegenerate)
	if !ok {
		return
	}
	code, _, ok := readCode(w, r)
	if !ok {
		return
	}
	if !user.TwoFactorEnabled {
		writeError(w, http.StatusConflict, problem.TwoFactorOff)
		return
	}
	entry := models.AuditLog{Verb: audit.VerbRegenerate, ResourceType: audit.KindTwoFactor, ResourceName: user.Username}
	method, err := s.checkCode(r, user, code, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if method == "" {
		entry.Outcome, entry.Reason = audit.Failed, "invalid_code"
		s.auditEvent(r, entry)
		writeError(w, http.StatusBadRequest, problem.TwoFactorInvalid)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err == nil {
		err = s.store.ReplaceRecoveryCodes(r.Context(), user.ID, hashes)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	entry.Details = audit.D{"two_factor_method": method}
	s.auditEvent(r, entry)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// handleTwoFactorDisable turns it off (code or recovery code), unless the policy requires it.
func (s *Server) handleTwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	user, policy, ok := s.twoFactorCaller(w, r, audit.VerbDisable)
	if !ok {
		return
	}
	code, _, ok := readCode(w, r)
	if !ok {
		return
	}
	entry := models.AuditLog{Verb: audit.VerbDisable, ResourceType: audit.KindTwoFactor, ResourceName: user.Username}
	if !user.TwoFactorEnabled {
		writeError(w, http.StatusConflict, problem.TwoFactorOff)
		return
	}
	if models.TwoFactorRequired(policy, user) {
		entry.Outcome, entry.Reason = audit.Denied, problem.TwoFactorRequired
		s.auditEvent(r, entry)
		writeError(w, http.StatusForbidden, problem.TwoFactorRequired)
		return
	}
	method, err := s.checkCode(r, user, code, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if method == "" {
		entry.Outcome, entry.Reason = audit.Failed, "invalid_code"
		s.auditEvent(r, entry)
		writeError(w, http.StatusBadRequest, problem.TwoFactorInvalid)
		return
	}
	if err := s.store.ResetTwoFactor(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	entry.Details = audit.D{"two_factor_method": method}
	s.auditEvent(r, entry)
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// handleResetUserTwoFactor (admin): removes the user's secret and recovery
// codes and ends their sessions; a required policy asks them to set it up
// again on the next sign-in.
func (s *Server) handleResetUserTwoFactor(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, problem.NotFound)
		return
	}
	noteFor(r).Name = user.Username
	if err := s.store.ResetTwoFactor(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if err := s.store.RevokeAllForUser(r.Context(), id); err != nil {
		slog.Warn("could not end sessions after two-factor reset", "user", user.Username, "error", err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

// newRecoveryCodes returns fresh codes (shown once) and their hashes (stored).
func newRecoveryCodes() ([]string, []string, error) {
	codes, err := auth.NewRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.HashRecoveryCode(c)
	}
	return codes, hashes, nil
}

// validTwoFactorPolicy: one of the four policies.
func validTwoFactorPolicy(p string) bool { return p == models.TwoFactorOff || models.TwoFactorOn(p) }
