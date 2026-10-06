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
	_, ignored := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if ctx.Err() != nil || ignored != nil || m.done {
		t.Fatal("q must not cancel or quit the scan")
	}
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

func TestAccountsPlannedCountsFailuresAndCached(t *testing.T) {
	m := New(nil)
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 30})
	for _, family := range []string{"storage", "sql", "compute", "iam"} {
		m.Update(ProgressMsg{Phase: "collector", Account: "demo", Scope: "projects/123", Collector: family, Status: "queued"})
	}
	m.Update(ProgressMsg{Phase: "collector", Scope: "projects/123", Collector: "metadata", Status: "completed"})
	m.Update(ProgressMsg{Phase: "collector", Account: "demo", Scope: "projects/123", Collector: "sql", Status: "completed", Failures: 2})
	m.Update(ProgressMsg{Phase: "collector", Account: "demo", Scope: "projects/demo", Collector: "storage", Status: "completed", Cached: true})
	m.Update(ProgressMsg{Phase: "collector", Account: "demo", Scope: "projects/123", Collector: "compute", Status: "started"})
	m.Update(ProgressMsg{Phase: "collector", Account: "demo", Scope: "projects/123", Collector: "iam", Status: "cancelled"})
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	view := m.View()
	if len(m.accounts) != 1 || !strings.Contains(view, "total=4 Q=0 R=1 C=1 F=1 X=1 cached=1") || !strings.Contains(view, "3/4 (75%)") {
		t.Fatal(view)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	p := m.accounts["demo"]["compute"]
	p.started = time.Now().Add(-3 * time.Second)
	m.accounts["demo"]["compute"] = p
	view = m.View()
	if !strings.Contains(view, "sql: partial") || !strings.Contains(view, "[cached]") || !strings.Contains(view, "iam: cancelled") {
		t.Fatal(view)
	}
	if strings.Contains(view, "compute: running • records=0 failures=0 • 0s") {
		t.Fatal("running elapsed must advance", view)
	}
}

func TestAccountsNavigationManyProjectsAndFamilies(t *testing.T) {
	m := New(nil)
	m.Update(tea.WindowSizeMsg{Width: 24, Height: 12})
	for i := 0; i < 150; i++ {
		for j := 0; j < 40; j++ {
			m.Update(ProgressMsg{Phase: "collector", Account: fmt.Sprintf("p%03d", i), Scope: "projects/123", Collector: fmt.Sprintf("family%02d", j), Status: "queued"})
		}
	}
	m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	if m.tab != 2 {
		t.Fatal("reverse navigation", m.tab)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if m.accountSelection != 149 {
		t.Fatal(m.accountSelection)
	}
	if !strings.Contains(m.View(), "p149") {
		t.Fatal(m.View())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if m.accountTop != 39 || !strings.Contains(m.View(), "family39") {
		t.Fatal(m.View())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyHome})
	if m.accountTop != 0 {
		t.Fatal(m.accountTop)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m.Update(tea.KeyMsg{Type: tea.KeyHome})
	if m.accountSelection != 0 {
		t.Fatal(m.accountSelection)
	}
	for _, line := range strings.Split(m.View(), "\n") {
		if len([]rune(line)) > 24 {
			t.Fatal(line)
		}
	}
	if len(strings.Split(m.View(), "\n")) > 12 {
		t.Fatal(m.View())
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd != nil || m.done {
		t.Fatal("q quit")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.tab != 0 {
		t.Fatal("forward navigation", m.tab)
	}
}

func TestModuleAndStageProgress(t *testing.T) {
	m := New(nil)
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 30})
	m.Update(ProgressMsg{Phase: "stage", Collector: "secrets", Status: "started"})
	if !strings.Contains(m.View(), "GCPBuster • secrets") {
		t.Fatal(m.View())
	}
	m.Update(ProgressMsg{Phase: "stage", Collector: "secrets", Status: "completed"})
	e := ProgressMsg{Phase: "module", Scope: "assessment", Collector: "check_one", Status: "queued", Total: 1000}
	m.Update(e)
	e.Status = "started"
	m.Update(e)
	key := "module / assessment / check_one"
	started := m.tasks[key].started
	e.Status = "progress"
	e.Count = 400
	e.Findings = 3
	m.Update(e)
	if m.tasks[key].started != started || m.tasks[key].status != "started" {
		t.Fatal("progress reset timing/state")
	}
	view := m.View()
	if !strings.Contains(view, "GCPBuster • assessing") || !strings.Contains(view, "assets=400/1000 findings=3") || !strings.Contains(view, "Collected records: 0") {
		t.Fatal(view)
	}
	if len(m.accounts) != 0 {
		t.Fatal("assessment created account rows")
	}
	if len(m.recent) != 1 {
		t.Fatal("progress flooded recent results", m.recent)
	}
	e.Status = "completed"
	e.Count = 1000
	m.Update(e)
	if m.tasks[key].status != "completed" {
		t.Fatal(m.tasks[key])
	}
	m.Update(DoneMsg{})
	if !strings.Contains(m.View(), "GCPBuster • finished") {
		t.Fatal(m.View())
	}
}
