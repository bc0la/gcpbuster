package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
)

func syntheticBatchCheck(n int) checks.Check {
	return checks.Check{ID: "synthetic_batch", Category: "best_practices", Types: []string{"test/Asset"}, Eval: func(a inventory.Asset, _ time.Time) []checks.Result {
		results := make([]checks.Result, n)
		for i := range results {
			results[i] = checks.Result{Severity: "INFO", Title: fmt.Sprintf("finding %s %d", a.Name, i), Evidence: inventory.Object{"index": i}}
		}
		return results
	}}
}

func syntheticAssessmentSnapshot() inventory.Snapshot {
	return inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//test/projects/123/assets/a", "test/Asset", inventory.Object{"name": "a"})}}
}

func persistedSyntheticCount(t *testing.T, e *engagement.Engagement) int {
	t.Helper()
	var n int
	if err := e.DB().QueryRow("SELECT count(*) FROM findings WHERE module='synthetic_batch'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func syntheticModuleStatus(t *testing.T, e *engagement.Engagement) string {
	t.Helper()
	var status string
	if err := e.DB().QueryRow("SELECT status FROM module_runs WHERE module='synthetic_batch'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestAssessmentBatchProgressAndFinalFlush(t *testing.T) {
	e := checkpointEngagement(t)
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	var events []inventory.ProgressEvent
	ctx := context.WithValue(context.Background(), progressSinkKey{}, func(event inventory.ProgressEvent) {
		events = append(events, event)
		if event.Phase == "module" && event.Status == "completed" {
			if n := persistedSyntheticCount(t, e); n != 600 {
				t.Fatalf("completed before final batch: %d", n)
			}
			if syntheticModuleStatus(t, e) != "completed" {
				t.Fatal("completed event before DB status")
			}
		}
	})
	cmd.SetContext(ctx)
	check := syntheticBatchCheck(600)
	original := check.Eval
	check.Eval = func(a inventory.Asset, now time.Time) []checks.Result {
		if syntheticModuleStatus(t, e) != "running" {
			t.Fatal("check not marked running")
		}
		return original(a, now)
	}
	if err := assess(ctx, cmd, e, syntheticAssessmentSnapshot(), []checks.Check{check}, false); err != nil {
		t.Fatal(err)
	}
	if n := persistedSyntheticCount(t, e); n != 600 {
		t.Fatal(n)
	}
	seenStarted, seenCompleted, exportStarted, exportCompleted := false, false, false, false
	for _, event := range events {
		if event.Phase == "module" && event.Status == "started" {
			seenStarted = true
		}
		if event.Phase == "module" && event.Status == "completed" {
			seenCompleted = true
			if event.Count != 1 || event.Total != 1 || event.Findings != 600 {
				t.Fatal(event)
			}
		}
		if event.Phase == "stage" && event.Collector == "report-export" {
			if event.Status == "started" {
				exportStarted = true
			}
			if event.Status == "completed" {
				exportCompleted = true
			}
		}
	}
	if !seenStarted || !seenCompleted || !exportStarted || !exportCompleted {
		t.Fatal(events)
	}
}

func TestAssessmentSecondBatchFailureAndResumeNoDuplicates(t *testing.T) {
	e := checkpointEngagement(t)
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	ctx := context.Background()
	if _, err := e.DB().Exec(`CREATE TRIGGER abort_second_batch BEFORE INSERT ON findings WHEN (SELECT count(*) FROM findings)>=256 BEGIN SELECT RAISE(ABORT,'synthetic batch failure'); END`); err != nil {
		t.Fatal(err)
	}
	check := syntheticBatchCheck(600)
	snap := syntheticAssessmentSnapshot()
	if err := assess(ctx, cmd, e, snap, []checks.Check{check}, false); err == nil {
		t.Fatal("failing batch accepted")
	}
	if n := persistedSyntheticCount(t, e); n != engagement.MaxFindingBatch {
		t.Fatal("first batch lost or second partly committed", n)
	}
	if syntheticModuleStatus(t, e) != "failed" {
		t.Fatal("failed batch marked completed")
	}
	if _, err := e.DB().Exec("DROP TRIGGER abort_second_batch"); err != nil {
		t.Fatal(err)
	}
	if err := assess(ctx, cmd, e, snap, []checks.Check{check}, true); err != nil {
		t.Fatal(err)
	}
	if n := persistedSyntheticCount(t, e); n != 600 {
		t.Fatal("resume duplicated partial findings", n)
	}
	if syntheticModuleStatus(t, e) != "completed" {
		t.Fatal("successful retry not completed")
	}
}

func TestAssessmentCancellationNeverCompletesModule(t *testing.T) {
	e := checkpointEngagement(t)
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []inventory.ProgressEvent
	ctx = context.WithValue(ctx, progressSinkKey{}, func(event inventory.ProgressEvent) { events = append(events, event) })
	cmd.SetContext(ctx)
	snap := syntheticAssessmentSnapshot()
	snap.Assets = append(snap.Assets, inventory.NewAsset("//test/projects/123/assets/b", "test/Asset", inventory.Object{"name": "b"}))
	check := syntheticBatchCheck(engagement.MaxFindingBatch)
	eval := check.Eval
	calls := 0
	check.Eval = func(a inventory.Asset, now time.Time) []checks.Result {
		calls++
		if calls == 2 {
			cancel()
		}
		return eval(a, now)
	}
	if err := assess(ctx, cmd, e, snap, []checks.Check{check}, false); err != context.Canceled {
		t.Fatal(err)
	}
	if n := persistedSyntheticCount(t, e); n != engagement.MaxFindingBatch {
		t.Fatal(n)
	}
	if syntheticModuleStatus(t, e) == "completed" {
		t.Fatal("cancelled module completed")
	}
	seenCancelled := false
	for _, event := range events {
		if event.Phase == "module" && event.Status == "completed" {
			t.Fatal(event)
		}
		if event.Status == "cancelled" {
			seenCancelled = true
		}
	}
	if !seenCancelled {
		t.Fatal(events)
	}
}
