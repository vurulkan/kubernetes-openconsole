package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// Keys says where the encryption key of the stored credentials comes from.
// Current nil: the key kept in the database itself (app_secrets), as every
// release before 2.23.1 did. Current set (ENCRYPTION_KEY_FILE /
// ENCRYPTION_KEY): the key lives outside the database; on start every value
// encrypted with the database key or with Previous is re-encrypted with
// Current in one transaction, and the database key is deleted.
type Keys struct {
	Current, Previous []byte
	// Lost (ENCRYPTION_KEY_LOST=true, for one start): the key a value was
	// encrypted with is gone. Values that can't be decrypted are emptied
	// (logged) instead of stopping the start; an admin enters them again.
	Lost bool
}

// encryptedColumns are every column holding a value encrypted by the store.
var encryptedColumns = []struct{ table, column string }{
	{"clusters", "kubeconfig_enc"}, {"clusters", "token_enc"}, {"clusters", "ca_cert_enc"}, {"clusters", "prometheus_enc"},
	{"kube_credentials", "kubeconfig_enc"}, {"kube_credentials", "token_enc"}, {"kube_credentials", "ca_cert_enc"},
	{"ldap_config", "bind_password_enc"},
	{"azure_ad_config", "client_secret_enc"},
}

// An external key's values are "v1:<key id>:<base64>"; values without the
// prefix are encrypted with the database key.
const keyPrefix = "v1:"

func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

func (s *Store) encrypt(plaintext string) (string, error) {
	if s.extKey == nil {
		return encrypt(s.key, plaintext)
	}
	enc, err := encrypt(s.extKey, plaintext)
	if err != nil || enc == "" {
		return enc, err
	}
	return keyPrefix + keyID(s.extKey) + ":" + enc, nil
}

func (s *Store) decrypt(encoded string) (string, error) {
	return decryptWith(encoded, s.key, s.extKey, nil)
}

// decryptWith decrypts a value with the key it names: the database key for
// an unprefixed value, else current or previous by key id.
func decryptWith(encoded string, dbKey, current, previous []byte) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, keyPrefix) {
		if dbKey == nil {
			return "", errors.New("value is encrypted with the database key, which is not in the database any more")
		}
		return decrypt(dbKey, encoded)
	}
	id, body, ok := strings.Cut(strings.TrimPrefix(encoded, keyPrefix), ":")
	switch {
	case !ok:
		return "", errors.New("malformed encrypted value")
	case current != nil && id == keyID(current):
		return decrypt(current, body)
	case previous != nil && id == keyID(previous):
		return decrypt(previous, body)
	}
	return "", fmt.Errorf("value is encrypted with key %s, which is neither ENCRYPTION_KEY nor ENCRYPTION_KEY_PREVIOUS", id)
}

// SigningKey signs the session JWTs. With an external key it is derived from
// it (so the same bytes are never used for two purposes); else the database
// key, as before.
func (s *Store) SigningKey() []byte {
	if s.extKey == nil {
		return s.key
	}
	m := hmac.New(sha256.New, s.extKey)
	m.Write([]byte("openconsole session signing"))
	return m.Sum(nil)
}

// setupKeys loads or creates the database key, or moves every value to the
// external key. It runs before the store is used.
func (s *Store) setupKeys(ctx context.Context, keys Keys) error {
	for _, k := range [][]byte{keys.Current, keys.Previous} {
		if k != nil && len(k) != 32 {
			return errors.New("an encryption key must be 32 bytes (openssl rand -base64 32)")
		}
	}
	if (keys.Previous != nil || keys.Lost) && keys.Current == nil {
		return errors.New("ENCRYPTION_KEY_PREVIOUS / ENCRYPTION_KEY_LOST need ENCRYPTION_KEY (or ENCRYPTION_KEY_FILE)")
	}
	dbKey, err := readDBKey(ctx, s.conn)
	if err != nil {
		return err
	}
	if keys.Current == nil {
		if dbKey == nil {
			if external, err := hasExternalValues(ctx, s.conn); err != nil {
				return err
			} else if external {
				return errors.New("the stored credentials are encrypted with an external key: set ENCRYPTION_KEY_FILE (or ENCRYPTION_KEY)")
			}
			if dbKey, err = createDBKey(ctx, s.conn); err != nil {
				return err
			}
		}
		s.key = dbKey
		return nil
	}
	s.extKey = keys.Current
	return s.reencrypt(ctx, dbKey, keys.Current, keys.Previous, keys.Lost)
}

func readDBKey(ctx context.Context, conn *sql.DB) ([]byte, error) {
	var key []byte
	err := conn.QueryRowContext(ctx, `SELECT encryption_key FROM app_secrets WHERE id = 1`).Scan(&key)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read encryption key: %w", err)
	case len(key) == 0:
		return nil, nil
	}
	return key, nil
}

func createDBKey(ctx context.Context, conn *sql.DB) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR REPLACE INTO app_secrets (id, encryption_key) VALUES (1, ?)`, key); err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}
	return key, nil
}

func hasExternalValues(ctx context.Context, conn *sql.DB) (bool, error) {
	for _, c := range encryptedColumns {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table+` WHERE CAST(`+c.column+` AS TEXT) LIKE 'v1:%'`).Scan(&n); err != nil {
			return false, fmt.Errorf("scan %s.%s: %w", c.table, c.column, err)
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// reencrypt moves every value not yet under current to current, and deletes
// the database key, in one transaction: a value that can't be decrypted
// stops the start and changes nothing, unless lost (then it is emptied).
func (s *Store) reencrypt(ctx context.Context, dbKey, current, previous []byte, lost bool) error {
	currentPrefix := keyPrefix + keyID(current) + ":"
	moved := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		for _, c := range encryptedColumns {
			rows, err := tx.QueryContext(ctx, `SELECT rowid, CAST(`+c.column+` AS TEXT) FROM `+c.table+
				` WHERE `+c.column+` IS NOT NULL AND CAST(`+c.column+` AS TEXT) != ''`)
			if err != nil {
				return fmt.Errorf("read %s.%s: %w", c.table, c.column, err)
			}
			type row struct {
				id  int64
				val string
			}
			var todo []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.val); err != nil {
					rows.Close()
					return err
				}
				if !strings.HasPrefix(r.val, currentPrefix) {
					todo = append(todo, r)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range todo {
				plain, err := decryptWith(r.val, dbKey, nil, previous)
				if err != nil && lost {
					slog.Warn("encryption key lost: value emptied, enter it again in Admin",
						slog.String("table", c.table), slog.String("column", c.column), slog.Int64("row", r.id))
					plain = ""
				} else if err != nil {
					return fmt.Errorf("%s.%s (row %d): %w (if that key is lost for good, start once with ENCRYPTION_KEY_LOST=true)", c.table, c.column, r.id, err)
				}
				enc, err := s.encrypt(plain)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE `+c.table+` SET `+c.column+` = ? WHERE rowid = ?`, enc, r.id); err != nil {
					return err
				}
				moved++
			}
		}
		if dbKey != nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM app_secrets`); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("move the stored credentials to the encryption key: %w", err)
	}
	if dbKey == nil && moved == 0 {
		return nil
	}
	// Rewrite the file so the old key and old ciphertexts don't linger in
	// free pages or the WAL.
	if _, err := s.conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum after moving to the encryption key: %w", err)
	}
	if _, err := s.conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint after moving to the encryption key: %w", err)
	}
	slog.Info("stored credentials moved to the encryption key", slog.String("key_id", keyID(current)), slog.Int("values", moved),
		slog.Bool("database_key_deleted", dbKey != nil))
	return nil
}
