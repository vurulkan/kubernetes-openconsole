package store

import (
	"context"
	"database/sql"
	"time"

	"k8s-dashboard/backend/internal/models"
)

// TwoFactor is a user's TOTP state: Secret is set from setup on, Enabled once
// a code confirmed it. A secret emptied by ENCRYPTION_KEY_LOST counts as off.
type TwoFactor struct {
	Secret   string
	Enabled  bool
	LastStep int64
}

func (s *Store) GetTwoFactor(ctx context.Context, userID int) (TwoFactor, error) {
	var enc string
	var enabled sql.NullTime
	var tf TwoFactor
	if err := s.conn.QueryRowContext(ctx, `SELECT totp_secret_enc, totp_enabled_at, totp_last_step FROM users WHERE id = ?`, userID).
		Scan(&enc, &enabled, &tf.LastStep); err != nil {
		return tf, err
	}
	secret, err := s.decrypt(enc)
	if err != nil {
		return tf, err
	}
	tf.Secret, tf.Enabled = secret, enabled.Valid && secret != ""
	return tf, nil
}

// SetPendingTOTP stores a new secret that isn't on yet (setup).
func (s *Store) SetPendingTOTP(ctx context.Context, userID int, secret string) error {
	enc, err := s.encrypt(secret)
	if err != nil {
		return err
	}
	_, err = s.conn.ExecContext(ctx, `UPDATE users SET totp_secret_enc = ?, totp_enabled_at = NULL, totp_last_step = 0 WHERE id = ?`, enc, userID)
	return err
}

// UseTOTPStep records step as used; false when it (or a later one) already
// was, so two requests with the same code can't both pass.
func (s *Store) UseTOTPStep(ctx context.Context, userID int, step int64) (bool, error) {
	res, err := s.conn.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// EnableTOTP turns the pending secret on, records the confirming step and
// replaces the recovery codes (their hashes).
func (s *Store) EnableTOTP(ctx context.Context, userID int, step int64, codeHashes []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_enabled_at = ?, totp_last_step = ? WHERE id = ?`, time.Now().UTC(), step, userID); err != nil {
			return err
		}
		return replaceRecoveryCodes(ctx, tx, userID, codeHashes)
	})
}

// ReplaceRecoveryCodes makes codeHashes the user's only recovery codes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int, codeHashes []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return replaceRecoveryCodes(ctx, tx, userID, codeHashes) })
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID int, codeHashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

// UseRecoveryCode spends the unused code with this hash; false if there is none.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int, codeHash string) (bool, error) {
	res, err := s.conn.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE id = (
		SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1)`,
		time.Now().UTC(), userID, codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecoveryCodesLeft counts the user's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID int) (int, error) {
	var n int
	err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ResetTwoFactor removes the secret and the recovery codes (turning off, admin reset).
func (s *Store) ResetTwoFactor(ctx context.Context, userID int) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_enc = '', totp_enabled_at = NULL, totp_last_step = 0 WHERE id = ?`, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID)
		return err
	})
}

// CountWithoutTwoFactor counts the active accounts policy would send to the
// set-up dialog on their next sign-in.
func (s *Store) CountWithoutTwoFactor(ctx context.Context, policy string) (int, error) {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range users {
		if users[i].IsActive && !users[i].TwoFactorEnabled && models.TwoFactorRequired(policy, &users[i]) {
			n++
		}
	}
	return n, nil
}
