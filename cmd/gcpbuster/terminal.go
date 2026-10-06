package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

type progressSinkKey struct{}

func progressSink(ctx context.Context) func(inventory.ProgressEvent) {
	f, _ := ctx.Value(progressSinkKey{}).(func(inventory.ProgressEvent))
	return f
}
func terminal(v any) bool {
	f, ok := v.(interface{ Fd() uintptr })
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}
func useTerminalUI(input io.Reader, output io.Writer, force, disabled bool) (bool, error) {
	if force && disabled {
		return false, errors.New("--ui and --no-ui cannot be combined")
	}
	available := terminal(input) && terminal(output) && os.Getenv("TERM") != "dumb"
	if force && !available {
		return false, errors.New("interactive UI requires terminal input/output; use --no-ui for redirected logs")
	}
	return !disabled && available, nil
}

func runWithTerminalUI(cmd *cobra.Command, args []string, run func(*cobra.Command, []string) error, force, disabled bool) error {
	enabled, err := useTerminalUI(cmd.InOrStdin(), cmd.ErrOrStderr(), force, disabled)
	if err != nil {
		return err
	}
	if !enabled {
		return run(cmd, args)
	}
	parent := cmd.Context()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	model := tui.New(cancel)
	program := tea.NewProgram(model, tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.ErrOrStderr()), tea.WithContext(ctx))
	send := func(e inventory.ProgressEvent) { program.Send(tui.ProgressMsg(e)) }
	cmd.SetContext(context.WithValue(ctx, progressSinkKey{}, send))
	originalOut, originalErr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	defer cmd.SetOut(originalOut)
	defer cmd.SetErr(originalErr)
	defer cmd.SetContext(parent)
	logs := tui.NewLogWriter(program.Send)
	cmd.SetOut(logs)
	cmd.SetErr(logs)
	done := make(chan error, 1)
	go func() { err := run(cmd, args); logs.Flush(); done <- err; program.Send(tui.DoneMsg{Err: err}) }()
	_, uiErr := program.Run()
	if uiErr != nil {
		cancel()
	}
	scanErr := <-done
	if scanErr != nil {
		return scanErr
	}
	if uiErr != nil {
		return uiErr
	}
	if dir, _ := cmd.Flags().GetString("engagement"); dir != "" {
		fmt.Fprintf(originalOut, "Report: %s/report.html\n", dir)
	}
	return nil
}
