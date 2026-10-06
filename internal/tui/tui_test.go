package tui

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestProgressTransitionsAndTabs(t *testing.T) {
	m := New(nil)
	e := ProgressMsg{Phase: "collector", Scope: "projects/123", Collector: "sql", Status: "started"}
	m.Update(e)
	if !strings.Contains(m.View(), "active 1") {
		t.Fatal(m.View())
	}
	e.Status = "completed"
	e.Count = 3
	m.Update(e)
	m.Update(e)
	if !strings.Contains(m.View(), "completed 1") || !strings.Contains(m.View(), "Collected records: 3") {
		t.Fatal(m.View())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if !strings.Contains(m.View(), "[Logs]") || !strings.Contains(m.View(), "records=3") {
		t.Fatal(m.View())
	}
}

func TestBoundedLogsResizeAndScroll(t *testing.T) {
	m := New(nil)
	for i := 0; i < 2000; i++ {
		m.Update(LogMsg(fmt.Sprintf("line %d", i)))
	}
	if len(m.logs) != maxLogs {
		t.Fatal(len(m.logs))
	}
	m.Update(tea.WindowSizeMsg{Width: 24, Height: 10})
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.offset != 1 {
		t.Fatal(m.offset)
	}
	for _, line := range strings.Split(m.View(), "\n") {
		if len([]rune(line)) > 24 {
			t.Fatal(line)
		}
	}
	if len(strings.Split(m.View(), "\n")) > 11 {
		t.Fatal(m.View())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if m.offset != 0 {
		t.Fatal(m.offset)
	}
}

func TestCancellationAndDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := New(cancel)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if ctx.Err() == nil || cmd == nil {
		t.Fatal("cancellation missing")
	}
	m = New(nil)
	_, cmd = m.Update(DoneMsg{Err: fmt.Errorf("do not expose raw error")})
	if cmd == nil || !m.done || strings.Contains(m.View(), "do not expose raw error") {
		t.Fatal(m.View())
	}
}

func TestLogWriterPartialControlAndBound(t *testing.T) {
	var msgs []tea.Msg
	w := NewLogWriter(func(m tea.Msg) { msgs = append(msgs, m) })
	w.Write([]byte("first"))
	w.Write([]byte(" line\nsecond\x1b\rline\n"))
	w.Write([]byte(strings.Repeat("x", 100000)))
	w.Flush()
	if len(msgs) != 3 || msgs[0] != LogMsg("first line") {
		t.Fatal(msgs)
	}
	if strings.ContainsAny(string(msgs[1].(LogMsg)), "\x1b\r") || len(string(msgs[2].(LogMsg))) > 1024 {
		t.Fatal("unbounded/control log")
	}
}

func TestSafeRequestMetadataAndFailureCount(t *testing.T) {
	m := New(nil)
	m.Update(ProgressMsg{Phase: "request", Host: "sqladmin.googleapis.com", Method: "GET", Status: "started"})
	m.Update(ProgressMsg{Phase: "request", Host: "sqladmin.googleapis.com", Method: "GET", Status: "failed", HTTPStatus: 403, RetryAfter: 2 * time.Second})
	if m.requests != 1 || m.requestFailures != 1 {
		t.Fatal(m.requests, m.requestFailures)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	// A wide view exposes all safe metadata, including retry throttling.
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 30})
	if !strings.Contains(m.View(), "HTTP=403") || !strings.Contains(m.View(), "retry-after=2s") {
		t.Fatal(m.View())
	}
}

func TestSchedulerQueueAndPartialCollector(t *testing.T) {
	m := New(nil)
	m.Update(ProgressMsg{Phase: "scheduler", Collector: "service-families", Total: 120, Queued: 112, Running: 8})
	m.Update(ProgressMsg{Phase: "collector", Scope: "projects/123", Collector: "sql", Status: "completed", Failures: 2})
	if !strings.Contains(m.View(), "queued 112") || !strings.Contains(m.View(), "failed/partial 1") {
		t.Fatal(m.View())
	}
	if strings.Contains(m.View(), "100%") {
		t.Fatal("dynamic hierarchy must not imply complete organization coverage")
	}
}

func TestProgramLifecycleAndCancellation(t *testing.T) {
	for _, cancelKey := range []bool{false, true} {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		cancelled := make(chan struct{}, 1)
		m := New(func() { cancelled <- struct{}{} })
		p := tea.NewProgram(m, tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutRenderer(), tea.WithoutSignalHandler(), tea.WithContext(ctx))
		done := make(chan error, 1)
		go func() { _, err := p.Run(); done <- err }()
		p.Send(ProgressMsg{Phase: "collector", Scope: "projects/123", Collector: "sql", Status: "started"})
		if cancelKey {
			p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
		} else {
			p.Send(DoneMsg{})
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("program failed to exit")
		}
		if !m.done {
			t.Fatal("done state missing")
		}
		if cancelKey {
			select {
			case <-cancelled:
			default:
				t.Fatal("scan cancellation missing")
			}
		}
	}
}
