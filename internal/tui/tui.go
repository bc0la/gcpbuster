// Package tui renders collection metadata only. Never send response bodies,
// credential values or exported findings to this terminal UI.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bc0la/gcpbuster/internal/inventory"
	tea "github.com/charmbracelet/bubbletea"
)

const maxLogs = 500

type ProgressMsg inventory.ProgressEvent
type LogMsg string
type DoneMsg struct{ Err error }
type tickMsg time.Time

type task struct {
	status          string
	started         time.Time
	count, failures int
	duration        time.Duration
	cached          bool
}
type Model struct {
	cancel                       context.CancelFunc
	started                      time.Time
	width, height, tab, offset   int
	tasks                        map[string]task
	schedulers                   map[string]inventory.ProgressEvent
	accounts                     map[string]map[string]task
	accountSelection, accountTop int
	accountExpanded              bool
	logs                         []string
	recent                       []string
	requests, requestFailures    int
	done                         bool
	Err                          error
}

func New(cancel context.CancelFunc) *Model {
	return &Model{cancel: cancel, started: time.Now(), width: 100, height: 30, tasks: make(map[string]task), schedulers: make(map[string]inventory.ProgressEvent), accounts: make(map[string]map[string]task)}
}

func tick() tea.Cmd            { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }
func (m *Model) Init() tea.Cmd { return tick() }
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(20, v.Width), max(8, v.Height)
	case tea.KeyMsg:
		switch v.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			m.done = true
			return m, tea.Quit
		case "tab", "right":
			m.tab = (m.tab + 1) % 3
			m.offset = 0
		case "shift+tab", "left":
			m.tab = (m.tab + 2) % 3
			m.offset = 0
		case "enter", " ":
			if m.tab == 2 {
				m.accountExpanded = !m.accountExpanded
				m.accountTop = 0
			}
		case "up", "k":
			if m.tab == 2 {
				m.accountMove(-1)
			} else {
				m.offset++
			}
		case "down", "j":
			if m.tab == 2 {
				m.accountMove(1)
			} else {
				m.offset = max(0, m.offset-1)
			}
		case "pgup":
			if m.tab == 2 {
				m.accountMove(-max(1, m.height-8))
			} else {
				m.offset += max(1, m.height-8)
			}
		case "pgdown":
			if m.tab == 2 {
				m.accountMove(max(1, m.height-8))
			} else {
				m.offset = max(0, m.offset-max(1, m.height-8))
			}
		case "home":
			if m.tab == 2 {
				m.accountMove(-1000000000)
			} else {
				m.offset = max(0, len(m.logs)-1)
			}
		case "end":
			if m.tab == 2 {
				m.accountMove(1000000000)
			} else {
				m.offset = 0
			}
		}
	case tickMsg:
		if !m.done {
			return m, tick()
		}
	case LogMsg:
		for _, line := range strings.Split(string(v), "\n") {
			if line != "" {
				m.appendLog(line)
			}
		}
	case ProgressMsg:
		e := inventory.ProgressEvent(v)
		if e.Phase == "scheduler" {
			m.schedulers[clean(e.Collector)] = e
		} else if e.Phase == "request" {
			if e.Status != "started" {
				m.requests++
				if e.Status == "failed" {
					m.requestFailures++
				}
			}
			m.appendLog(fmt.Sprintf("request %-9s %s %s HTTP=%d attempt=%d elapsed=%s reason=%s retry-after=%s", e.Status, e.Method, e.Host, e.HTTPStatus, e.Attempt, e.Duration.Round(time.Millisecond), e.Reason, e.RetryAfter))
		} else if e.Phase == "collector" || e.Phase == "hierarchy" || e.Phase == "module" {
			key := clean(e.Phase + " / " + e.Scope + " / " + e.Collector)
			p := m.tasks[key]
			if e.Status == "started" {
				p.started = time.Now()
			}
			p.status, p.count, p.failures, p.duration = e.Status, e.Count, e.Failures, e.Duration
			p.cached = e.Cached || e.Status == "cached"
			m.tasks[key] = p
			if e.Phase == "collector" && e.Account != "" {
				account := clean(e.Account)
				if m.accounts[account] == nil {
					m.accounts[account] = make(map[string]task)
				}
				m.accounts[account][clean(e.Collector)] = p
			}
			line := fmt.Sprintf("%s: %s records=%d failures=%d elapsed=%s", key, e.Status, e.Count, e.Failures, e.Duration.Round(time.Millisecond))
			m.appendLog(line)
			if e.Status != "started" && e.Status != "queued" {
				m.recent = append(m.recent, clean(line))
				if len(m.recent) > 8 {
					m.recent = m.recent[len(m.recent)-8:]
				}
			}
		} else {
			m.appendLog(fmt.Sprintf("%s %s %s: %s records=%d", e.Phase, e.Scope, e.Collector, e.Status, e.Count))
		}
	case DoneMsg:
		m.done, m.Err = true, v.Err
		if v.Err != nil {
			m.appendLog("Scan stopped; review the sanitized CLI error and coverage failures.")
		}
		return m, tea.Quit
	}
	m.offset = min(m.offset, max(0, len(m.logs)-1))
	return m, nil
}

func (m *Model) accountNames() []string {
	var names []string
	for name := range m.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (m *Model) accountMove(delta int) {
	if m.accountExpanded {
		names := m.accountNames()
		if len(names) > 0 {
			n := len(m.accounts[names[min(m.accountSelection, len(names)-1)]])
			m.accountTop = min(max(0, m.accountTop+delta), max(0, n-1))
		}
	} else {
		m.accountSelection = min(max(0, m.accountSelection+delta), max(0, len(m.accounts)-1))
	}
}

func (m *Model) renderAccounts() []string {
	names := m.accountNames()
	if len(names) == 0 {
		return []string{"Waiting for verified projects and planned collectors…"}
	}
	m.accountSelection = min(m.accountSelection, len(names)-1)
	rows := []string{"Project totals grow as collection stages are discovered; partial/denied reads are failures."}
	available := max(1, m.height-9)
	if m.accountExpanded {
		name := names[m.accountSelection]
		rows = append(rows, "Project: "+name, "Collector groups / status / records / failures / elapsed / cached")
		var families []string
		for family := range m.accounts[name] {
			families = append(families, family)
		}
		sort.Strings(families)
		start := min(m.accountTop, max(0, len(families)-1))
		end := min(len(families), start+available)
		for _, family := range families[start:end] {
			p := m.accounts[name][family]
			state := p.status
			if state == "started" {
				state = "running"
			}
			if p.failures > 0 && state == "completed" {
				state = "partial"
			}
			cached := ""
			if p.cached {
				cached = " [cached]"
			}
			elapsed := p.duration
			if p.status == "started" {
				elapsed = time.Since(p.started)
			}
			rows = append(rows, fmt.Sprintf("%s: %s • records=%d failures=%d • %s%s", family, state, p.count, p.failures, elapsed.Round(time.Millisecond), cached))
		}
		rows = append(rows, fmt.Sprintf("Families %d–%d of %d • Enter to return to project list", start+1, end, len(families)))
	} else {
		start := max(0, m.accountSelection-available+1)
		end := min(len(names), start+available)
		rows = append(rows, "Project • collector groups: finished/total queued running completed failed cancelled cached")
		for i, name := range names[start:end] {
			q, r, c, f, x, cached := 0, 0, 0, 0, 0, 0
			for _, p := range m.accounts[name] {
				if p.cached {
					cached++
				}
				switch p.status {
				case "queued":
					q++
				case "started":
					r++
				case "completed", "cached":
					if p.failures > 0 {
						f++
					} else {
						c++
					}
				case "failed", "partial":
					f++
				case "cancelled":
					x++
				}
			}
			marker := " "
			if start+i == m.accountSelection {
				marker = ">"
			}
			total := len(m.accounts[name])
			terminal := c + f + x
			rows = append(rows, fmt.Sprintf("%s %s • %d/%d (%d%%) total=%d Q=%d R=%d C=%d F=%d X=%d cached=%d", marker, name, terminal, total, terminal*100/max(1, total), total, q, r, c, f, x, cached))
		}
		rows = append(rows, fmt.Sprintf("Projects %d–%d of %d • Enter expands selected project", start+1, end, len(names)))
	}
	return rows
}

func (m *Model) appendLog(line string) {
	if m.offset > 0 {
		m.offset++
	}
	m.logs = append(m.logs, clean(line))
	if len(m.logs) > maxLogs {
		m.logs = m.logs[len(m.logs)-maxLogs:]
	}
}

// clean removes terminal control sequences and limits each metadata line. It
// is not a credential detector: callers must only pass sanitized metadata.
func clean(s string) string {
	r := make([]rune, 0, min(len(s), 1024))
	for _, c := range s {
		if !unicode.IsControl(c) {
			r = append(r, c)
			if len(r) >= 1024 {
				break
			}
		}
	}
	return string(r)
}

func (m *Model) View() string {
	state := "collecting"
	if m.done {
		state = "finished"
		if m.Err != nil {
			state = "stopped"
		}
	}
	header := fmt.Sprintf("GCPBuster • %s • elapsed %s", state, time.Since(m.started).Truncate(time.Second))
	tabs := "[Progress]  Logs  Accounts"
	if m.tab == 1 {
		tabs = "Progress  [Logs]  Accounts"
	} else if m.tab == 2 {
		tabs = "Progress  Logs  [Accounts]"
	}
	lines := []string{header, tabs, ""}
	if m.tab == 1 {
		end := max(0, len(m.logs)-m.offset)
		start := max(0, end-max(1, m.height-7))
		if end == 0 {
			lines = append(lines, "Waiting for safe collection logs…")
		} else {
			lines = append(lines, m.logs[start:end]...)
		}
	} else if m.tab == 2 {
		lines = append(lines, m.renderAccounts()...)
	} else {
		active, completed, failed, skipped, records, queued, cancelled := 0, 0, 0, 0, 0, 0, 0
		var running []string
		for k, p := range m.tasks {
			records += p.count
			switch p.status {
			case "queued":
				queued++
			case "cancelled":
				cancelled++
			case "started":
				active++
				running = append(running, fmt.Sprintf("  ▸ %s (%s)", k, time.Since(p.started).Truncate(time.Second)))
			case "completed", "cached":
				if p.failures > 0 {
					failed++
				} else {
					completed++
				}
			case "failed", "partial":
				failed++
			case "skipped":
				skipped++
			}
		}
		lines = append(lines, fmt.Sprintf("Discovered work: %d • active %d • completed %d • failed/partial %d • skipped %d", len(m.tasks), active, completed, failed, skipped), fmt.Sprintf("Collected records: %d • HTTP requests: %d • HTTP failures: %d", records, m.requests, m.requestFailures), "Totals grow as projects/services are discovered; failures are not evidence of safety.", "", "Active collectors:")
		lines = append(lines, fmt.Sprintf("Collector groups: queued %d • cancelled %d", queued, cancelled))
		var stages []string
		for stage := range m.schedulers {
			stages = append(stages, stage)
		}
		sort.Strings(stages)
		for _, stage := range stages {
			e := m.schedulers[stage]
			if e.Queued > 0 || e.Running > 0 {
				lines = append(lines, fmt.Sprintf("Queue %s: total %d • queued %d • running %d • done %d • cancelled %d", stage, e.Total, e.Queued, e.Running, e.Completed, e.Cancelled))
			}
		}
		sort.Strings(running)
		if len(running) == 0 {
			running = []string{"  Waiting for collection or assessment…"}
		}
		limit := max(1, (m.height-14)/2)
		lines = append(lines, running[:min(limit, len(running))]...)
		if len(running) > limit {
			lines = append(lines, fmt.Sprintf("  … %d more active", len(running)-limit))
		}
		lines = append(lines, "", "Recent collector results:")
		for i := len(m.recent) - 1; i >= 0 && len(lines) < m.height-3; i-- {
			lines = append(lines, "  "+m.recent[i])
		}
	}
	if len(lines) > m.height-2 {
		lines = lines[:m.height-2]
	}
	footer := "tab: Progress/Logs/Accounts • ↑/↓ pgup/pgdown: scroll logs • end: follow • ctrl+c: cancel"
	if m.tab == 2 {
		footer = "↑/↓: projects • enter: expand/collapse • ↑/↓: expanded families • tab: switch • ctrl+c: cancel"
	}
	lines = append(lines, "", footer)
	for i, line := range lines {
		r := []rune(line)
		if len(r) > m.width {
			lines[i] = string(r[:max(1, m.width-1)]) + "…"
		}
	}
	return strings.Join(lines, "\n")
}

// LogWriter serializes safe CLI status writes. Partial lines and its history
// are bounded; it does not write any files or retain raw findings.
type LogWriter struct {
	mu      sync.Mutex
	send    func(tea.Msg)
	pending string
}

func NewLogWriter(send func(tea.Msg)) *LogWriter { return &LogWriter{send: send} }
func (w *LogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			if w.send != nil && w.pending != "" {
				w.send(LogMsg(clean(w.pending)))
			}
			w.pending = ""
		} else if len(w.pending) < 4096 {
			w.pending += string([]byte{b})
		}
	}
	return len(p), nil
}
func (w *LogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != "" && w.send != nil {
		w.send(LogMsg(clean(w.pending)))
	}
	w.pending = ""
}
