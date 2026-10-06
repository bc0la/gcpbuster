package engagement

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/findings"
)

func batchEngagement(t *testing.T) *Engagement {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func findingCount(t *testing.T, e *Engagement) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteBatchPreservesSingleWriteFields(t *testing.T) {
	e := batchEngagement(t)
	ctx := context.Background()
	f := findings.Finding{ProjectID: "project", Region: "region", Module: "module", Severity: findings.SevHigh, ResourceName: "resource", Title: "title", Detail: map[string]any{"actual": "value"}, RawOutputPath: "secret-hits/example.txt", CreatedAt: time.Date(2026, 10, 6, 1, 2, 3, 0, time.UTC)}
	if err := e.Write(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteBatch(ctx, []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	var same int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM findings a JOIN findings b ON a.id=1 AND b.id=2 AND a.project_id=b.project_id AND a.region=b.region AND a.module=b.module AND a.severity=b.severity AND a.resource_name=b.resource_name AND a.title=b.title AND a.detail_json=b.detail_json AND a.raw_output_path=b.raw_output_path AND a.created_at=b.created_at`).Scan(&same); err != nil || same != 1 {
		t.Fatalf("single/batch fields differ: %d %v", same, err)
	}
	if err := e.WriteBatch(ctx, []findings.Finding{{Title: "unset defaults"}}); err != nil {
		t.Fatal(err)
	}
	var detail string
	var created any
	var raw any
	if err := e.db.QueryRow(`SELECT detail_json,created_at,raw_output_path FROM findings WHERE id=3`).Scan(&detail, &created, &raw); err != nil {
		t.Fatal(err)
	}
	if detail != "{}" || created == nil || raw != nil {
		t.Fatal("default fields changed")
	}
}

func TestWriteBatchRollbackAndBound(t *testing.T) {
	e := batchEngagement(t)
	ctx := context.Background()
	if _, err := e.db.Exec(`CREATE TRIGGER reject_batch_title BEFORE INSERT ON findings WHEN NEW.title='reject' BEGIN SELECT RAISE(ABORT, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteBatch(ctx, []findings.Finding{{Title: "first"}, {Title: "reject"}, {Title: "last"}}); err == nil {
		t.Fatal("SQL failure accepted")
	}
	if findingCount(t, e) != 0 {
		t.Fatal("SQL failure left partial rows")
	}
	if err := e.WriteBatch(ctx, []findings.Finding{{Title: "first"}, {Detail: make(chan int)}}); err == nil {
		t.Fatal("serialization failure accepted")
	}
	if findingCount(t, e) != 0 {
		t.Fatal("serialization failure left rows")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.WriteBatch(cancelled, []findings.Finding{{Title: "cancelled"}}); err == nil {
		t.Fatal("cancelled context accepted")
	}
	if findingCount(t, e) != 0 {
		t.Fatal("cancellation left rows")
	}
	if err := e.WriteBatch(ctx, make([]findings.Finding, MaxFindingBatch+1)); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	if err := e.WriteBatch(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteBatch(ctx, make([]findings.Finding, MaxFindingBatch)); err != nil {
		t.Fatal(err)
	}
	if findingCount(t, e) != MaxFindingBatch {
		t.Fatal("full batch incomplete")
	}
}
