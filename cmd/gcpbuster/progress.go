package main

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

// Share one writer lock with command messages and the heartbeat. Progress must
// not interleave lines or race callers using a bytes.Buffer as stderr.
type progressWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(p)
}

type scanProgress struct {
	writer                     *progressWriter
	verbose                    bool
	mu                         sync.Mutex
	active, finished, requests int
	started                    time.Time
	stop                       chan struct{}
	done                       chan struct{}
	once                       sync.Once
	sink                       func(inventory.ProgressEvent)
	activeTasks                map[string]bool
}

func newScanProgress(w io.Writer, verbose bool) *scanProgress {
	return newScanProgressWithSink(w, verbose, nil)
}

func newScanProgressWithSink(w io.Writer, verbose bool, sink func(inventory.ProgressEvent)) *scanProgress {
	p := &scanProgress{writer: &progressWriter{out: w}, verbose: verbose, started: time.Now(), stop: make(chan struct{}), done: make(chan struct{}), sink: sink, activeTasks: make(map[string]bool)}
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				if p.sink != nil {
					continue
				}
				p.mu.Lock()
				fmt.Fprintf(p.writer, "Progress: %d collectors active, %d finished, %d requests completed (%s elapsed)\n", p.active, p.finished, p.requests, time.Since(p.started).Round(time.Second))
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *scanProgress) Close() { p.once.Do(func() { close(p.stop); <-p.done }) }

func (p *scanProgress) Report(e inventory.ProgressEvent) {
	if p.sink != nil {
		p.sink(e)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.Phase == "scheduler" {
		if e.Status == "started" || e.Status == "completed" || e.Status == "cancelled" {
			fmt.Fprintf(p.writer, "Scheduler %s: %s (total=%d queued=%d running=%d completed=%d cancelled=%d)\n", e.Collector, e.Status, e.Total, e.Queued, e.Running, e.Completed, e.Cancelled)
		}
		return
	}
	if e.Phase == "collector" {
		key := e.Scope + "\x00" + e.Collector
		if e.Status == "started" {
			if !p.activeTasks[key] {
				p.active++
				p.activeTasks[key] = true
			}
		} else if e.Status == "completed" || e.Status == "failed" || e.Status == "cancelled" {
			if p.activeTasks[key] {
				p.active--
				delete(p.activeTasks, key)
			}
			p.finished++
		}
		if e.Status == "queued" && !p.verbose {
			return
		}
	}
	if e.Phase == "request" {
		if e.Status != "started" {
			p.requests++
		}
		if !p.verbose {
			return
		}
		fmt.Fprintf(p.writer, "  Request %s %s: %s (attempt %d, HTTP %d, %s header/transport time, reason=%s, retry-after=%s)\n", e.Method, e.Host, e.Status, e.Attempt, e.HTTPStatus, e.Duration.Round(time.Millisecond), e.Reason, e.RetryAfter.Round(time.Millisecond))
		return
	}
	if e.Status == "started" {
		fmt.Fprintf(p.writer, "[%s] %s %s: started\n", e.Scope, e.Phase, e.Collector)
	} else {
		fmt.Fprintf(p.writer, "[%s] %s %s: %s (%d records, %d incomplete/failed, %s)\n", e.Scope, e.Phase, e.Collector, e.Status, e.Count, e.Failures, e.Duration.Round(time.Millisecond))
	}
}
