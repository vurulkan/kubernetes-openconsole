package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/models"
)

func TestTerminationHistory(t *testing.T) {
	_, s := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()
	t0 := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	exit := func(code int, reason string, at time.Time) models.ContainerTermination {
		return models.ContainerTermination{Namespace: "shop", Pod: "web-1", Container: "app", Owner: "Deployment/web", ExitCode: code, Reason: reason, FirstAt: at, LastAt: at}
	}
	record := func(e models.ContainerTermination) {
		t.Helper()
		if err := s.RecordTermination(ctx, 1, e); err != nil {
			t.Fatal(err)
		}
	}
	// A crash loop: five OOM kills are one row ×5; the same exit seen again (resync) changes nothing.
	for i := 0; i < 5; i++ {
		record(exit(137, "OOMKilled", t0.Add(time.Duration(i)*time.Minute)))
	}
	record(exit(137, "OOMKilled", t0.Add(4*time.Minute)))
	// Then a different exit: a new row.
	record(exit(1, "Error", t0.Add(10*time.Minute)))
	// Another cluster's history stays apart.
	if err := s.RecordTermination(ctx, 2, exit(2, "Error", t0)); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListTerminations(ctx, 1, "shop", "Deployment/web", "", t0.Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Reason != "Error" || rows[1].Count != 5 ||
		!rows[1].FirstAt.Equal(t0) || !rows[1].LastAt.Equal(t0.Add(4*time.Minute)) {
		t.Fatalf("rows = %+v", rows)
	}
	if byPod, _ := s.ListTerminations(ctx, 1, "shop", "", "web-1", t0.Add(-time.Hour), 100); len(byPod) != 2 {
		t.Fatalf("by pod = %+v", byPod)
	}

	if err := s.PurgeTerminations(ctx, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.ListTerminations(ctx, 1, "shop", "Deployment/web", "", t0.Add(-time.Hour), 100); len(rows) != 1 || rows[0].Reason != "Error" {
		t.Fatalf("after purge = %+v", rows)
	}
}
