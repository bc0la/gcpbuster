package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/spf13/cobra"
)

func TestTerminalSelectionNonInteractive(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	for _, tt := range []struct{ force, disabled, wantErr bool }{{false, false, false}, {false, true, false}, {true, false, true}, {true, true, true}} {
		got, err := useTerminalUI(strings.NewReader(""), &bytes.Buffer{}, tt.force, tt.disabled)
		if got || (err != nil) != tt.wantErr {
			t.Fatalf("force=%v disabled=%v enabled=%v err=%v", tt.force, tt.disabled, got, err)
		}
	}
}

func TestTerminalSelectionTTY(t *testing.T) {
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	defer f.Close()
	if !terminal(f) {
		t.Skip("PTY not detected as terminal")
	}
	t.Setenv("TERM", "xterm-256color")
	for _, tt := range []struct{ force, disabled, enabled bool }{{false, false, true}, {true, false, true}, {false, true, false}} {
		got, err := useTerminalUI(f, f, tt.force, tt.disabled)
		if err != nil || got != tt.enabled {
			t.Fatalf("enabled=%v err=%v", got, err)
		}
	}
	t.Setenv("TERM", "dumb")
	if got, err := useTerminalUI(f, f, false, false); got || err != nil {
		t.Fatal(got, err)
	}
	if _, err := useTerminalUI(f, f, true, false); err == nil {
		t.Fatal("forced dumb terminal must reject")
	}
}

func TestTerminalFallbackPreservesCommandAndError(t *testing.T) {
	var out, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	ctx := context.WithValue(context.Background(), struct{}{}, "original")
	cmd.SetContext(ctx)
	want := errors.New("scan failed")
	called := false
	err := runWithTerminalUI(cmd, []string{"argument"}, func(c *cobra.Command, args []string) error {
		called = true
		if c.Context() != ctx || progressSink(c.Context()) != nil || len(args) != 1 || args[0] != "argument" {
			t.Fatal("fallback modified command")
		}
		io.WriteString(c.OutOrStdout(), "plain output\n")
		io.WriteString(c.ErrOrStderr(), "plain diagnostic\n")
		return want
	}, false, false)
	if !called || err != want || out.String() != "plain output\n" || stderr.String() != "plain diagnostic\n" || cmd.Context() != ctx {
		t.Fatal(called, err, out.String(), stderr.String())
	}
}

func TestProgressSinkIsContextScoped(t *testing.T) {
	ctx := context.Background()
	if progressSink(ctx) != nil {
		t.Fatal("unexpected default sink")
	}
	called := false
	ctx = context.WithValue(ctx, progressSinkKey{}, func(e inventory.ProgressEvent) { called = e.Phase == "test" })
	progressSink(ctx)(inventory.ProgressEvent{Phase: "test"})
	if !called {
		t.Fatal("missing progress sink")
	}
}

func TestTerminalForcedUnavailableDoesNotStartScan(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))
	cmd.SetErr(&bytes.Buffer{})
	called := false
	err := runWithTerminalUI(cmd, nil, func(*cobra.Command, []string) error { called = true; return nil }, true, false)
	if err == nil || called {
		t.Fatal("unavailable forced UI ran scan")
	}
}
