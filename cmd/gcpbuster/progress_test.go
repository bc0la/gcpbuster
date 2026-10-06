package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestScanProgressDetailAndConcurrentOutput(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var output bytes.Buffer
		p := newScanProgress(&output, verbose)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.Report(inventory.ProgressEvent{Phase: "collector", Scope: "projects/123", Collector: "compute", Status: "started"})
				p.Report(inventory.ProgressEvent{Phase: "request", Method: "GET", Host: "compute.googleapis.com", Status: "completed", Attempt: 1, HTTPStatus: 200, Duration: time.Second})
				p.Report(inventory.ProgressEvent{Phase: "collector", Scope: "projects/123", Collector: "compute", Status: "completed", Count: 3, Failures: 1, Duration: time.Second})
			}()
		}
		wg.Wait()
		p.Close()
		p.Close()
		if p.active != 0 || p.finished != 8 || p.requests != 8 {
			t.Fatal(p.active, p.finished, p.requests)
		}
		text := output.String()
		if strings.Count(text, "collector compute: started") != 8 || strings.Count(text, "3 records, 1 incomplete/failed") != 8 {
			t.Fatal(text)
		}
		if strings.Contains(text, "Request GET") != verbose {
			t.Fatal("request detail policy", text)
		}
	}
}

func TestScanConcurrencyFlagValidationAndDefaults(t *testing.T) {
	cmd := scanCommand()
	value, err := cmd.Flags().GetInt("concurrency")
	if err != nil || value != 8 {
		t.Fatal(value, err)
	}
	if cmd.Flags().Lookup("verbose") == nil {
		t.Fatal("verbose flag missing")
	}
	for _, value := range []string{"0", "65", "-1"} {
		cmd := rootCommand()
		cmd.SetArgs([]string{"scan", "--concurrency", value})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--concurrency") {
			t.Fatal(value, err)
		}
	}
}
