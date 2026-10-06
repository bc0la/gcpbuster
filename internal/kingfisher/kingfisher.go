// Package kingfisher scans explicitly supplied samples locally. It never enables
// credential validation, provider enumeration, archive extraction or update checks.
package kingfisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("kingfisher executable unavailable")

type Sample struct{ ID, Source, Region, Content string }
type Options struct {
	Redact  bool
	Timeout time.Duration
}
type Finding struct {
	SampleID   string `json:"sample_id"`
	Source     string `json:"source"`
	Region     string `json:"region"`
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Snippet    string `json:"snippet"`
	Confidence string `json:"confidence"`
	Validation string `json:"validation"`
	Severity   string `json:"severity"`
	Line       int    `json:"line"`
}
type Report struct {
	Findings                 []Finding
	Warnings                 []string
	SamplesScanned, ExitCode int
}

const maxSamples = 10000
const maxSampleBytes = 4 << 20
const maxTotalBytes = 64 << 20
const maxOutputBytes = 32 << 20
const maxFindings = 10000

// Run resolves only the fixed kingfisher executable, not a caller-supplied command.
// Content and findings can contain credentials. No samples or raw stderr are logged.
// Full snippets are returned unless Redact is explicitly selected.
func Run(ctx context.Context, samples []Sample, options Options) (Report, error) {
	binary, err := resolveBinary(exec.LookPath, os.Executable)
	if err != nil {
		return Report{}, ErrUnavailable
	}
	return run(ctx, binary, samples, options)
}

func run(ctx context.Context, binary string, samples []Sample, options Options) (Report, error) {
	report := Report{ExitCode: -1}
	if len(samples) > maxSamples {
		return report, errors.New("kingfisher sample count exceeds limit")
	}
	seen := map[string]bool{}
	total := 0
	for _, s := range samples {
		if s.ID == "" || len(s.ID) > 512 || seen[s.ID] || len(s.Content) > maxSampleBytes {
			return report, errors.New("invalid or oversized kingfisher sample")
		}
		seen[s.ID] = true
		total += len(s.Content)
		if total > maxTotalBytes {
			return report, errors.New("kingfisher total sample bytes exceed limit")
		}
	}
	if len(samples) == 0 {
		report.ExitCode = 0
		return report, nil
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	if timeout <= 0 || timeout > 10*time.Minute {
		return report, errors.New("invalid kingfisher timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "gcpbuster-kingfisher-")
	if err != nil {
		return report, errors.New("cannot stage kingfisher samples")
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		return report, errors.New("cannot protect kingfisher staging directory")
	}
	paths := map[string]Sample{}
	for _, s := range samples {
		name := fmt.Sprintf("%x.txt", sha256.Sum256([]byte(s.ID)))
		path := filepath.Join(dir, name)
		if err = os.WriteFile(path, []byte(s.Content), 0600); err != nil {
			return report, errors.New("cannot stage kingfisher sample")
		}
		paths[path] = s
		paths[name] = s
		paths["./"+name] = s
	}
	cmd := exec.CommandContext(ctx, binary, "scan", dir, "--format", "json", "--git-history", "none", "--no-validate", "--no-update-check", "--no-extract-archives", "--no-rule-cache", "--jobs", "2")
	cmd.Dir = dir
	// Do not inherit alert endpoints, tokens, proxies, custom configuration or logs.
	cmd.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	cmd.WaitDelay = time.Second
	stdout := &boundedOutput{limit: maxOutputBytes, cancel: cancel}
	stderr := &boundedOutput{limit: 64 << 10, cancel: cancel, discard: true}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if cmd.ProcessState != nil {
		report.ExitCode = cmd.ProcessState.ExitCode()
	}
	report.Findings, report.Warnings = parse(stdout.buf.Bytes(), paths, options.Redact)
	report.SamplesScanned = len(samples)
	if stdout.overflow || stderr.overflow {
		return report, errors.New("kingfisher output limit exceeded")
	}
	if ctx.Err() != nil {
		return report, errors.New("kingfisher scan canceled or timed out")
	}
	if err != nil && report.ExitCode != 200 && report.ExitCode != 205 {
		return report, errors.New("kingfisher scan failed")
	}
	return report, nil
}

type boundedOutput struct {
	mu                sync.Mutex
	buf               bytes.Buffer
	limit, n          int
	cancel            context.CancelFunc
	overflow, discard bool
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := w.limit - w.n
	if remaining < 0 {
		remaining = 0
	}
	keep := n
	if keep > remaining {
		keep = remaining
		w.overflow = true
		w.cancel()
	}
	if !w.discard {
		w.buf.Write(p[:keep])
	}
	w.n += keep
	return n, nil
}
