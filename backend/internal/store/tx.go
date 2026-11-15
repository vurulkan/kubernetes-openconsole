package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrUnknownReference: a write named a user, group or role that doesn't
// exist (SQLite: FOREIGN KEY constraint failed).
var ErrUnknownReference = errors.New("unknown user, group or role")

func fkErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		return ErrUnknownReference
	}
	return err
}

// inTx runs fn in one transaction. (A failed COMMIT leaves the connection
// clean: modernc.org/sqlite rolls back itself since 1.3x; 1.29 left it inside
// the transaction and later writes were lost, see TestFailedCommitLeavesTheConnectionUsable.)
func (s *Store) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return fkErr(err)
	}
	return fkErr(tx.Commit())
}
