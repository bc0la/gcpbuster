package main

import (
	"fmt"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/spf13/cobra"
)

// Assessment events contain counters and fixed check/stage identifiers only.
func assessmentProgress(cmd *cobra.Command, event inventory.ProgressEvent) {
	if sink := progressSink(cmd.Context()); sink != nil {
		sink(event)
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s %s: %s (%d/%d records scanned, %d findings, %s)\n", event.Phase, event.Collector, event.Status, event.Count, event.Total, event.Findings, event.Duration.Round(time.Millisecond))
}

func assessmentStage(cmd *cobra.Command, name string) func() {
	start := time.Now()
	assessmentProgress(cmd, inventory.ProgressEvent{Phase: "stage", Scope: "assessment", Collector: name, Status: "started"})
	return func() {
		assessmentProgress(cmd, inventory.ProgressEvent{Phase: "stage", Scope: "assessment", Collector: name, Status: "completed", Duration: time.Since(start)})
	}
}
