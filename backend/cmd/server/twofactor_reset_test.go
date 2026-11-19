package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/db"
	"k8s-dashboard/backend/internal/store"
)

// TWO_FACTOR_RESET_USER removes the account's two-factor sign-in and records it.
func TestResetTwoFactorOnStart(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st, err := store.New(database.Conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, _ := st.CreateUser(ctx, "ops", "x")
	_ = st.SetPendingTOTP(ctx, id, "JBSWY3DPEHPK3PXP")
	_ = st.EnableTOTP(ctx, id, 1, []string{"h"})
	if tf, _ := st.GetTwoFactor(ctx, id); !tf.Enabled {
		t.Fatal("setup")
	}
	resetTwoFactor(st, audit.New(st), "ops")
	resetTwoFactor(st, audit.New(st), "nobody") // logged, nothing else
	if tf, _ := st.GetTwoFactor(ctx, id); tf.Enabled || tf.Secret != "" {
		t.Fatalf("still on: %+v", tf)
	}
	if n, _ := st.RecoveryCodesLeft(ctx, id); n != 0 {
		t.Fatalf("recovery codes left: %d", n)
	}
	for i := 0; i < 100; i++ {
		var n int
		_ = database.Conn.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'two_factor.reset' AND user = 'system' AND resource_name = 'ops'`).Scan(&n)
		if n == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("two_factor.reset not audited")
}
