package engagement

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bc0la/gcpbuster/internal/findings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  alias TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME
);
CREATE TABLE IF NOT EXISTS module_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL,
  module TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME,
  UNIQUE(project_id, module)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL,
  severity TEXT NOT NULL,
  resource_name TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  raw_output_path TEXT,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT,
  module TEXT,
  level TEXT NOT NULL,
  msg TEXT NOT NULL,
  created_at DATETIME NOT NULL
);
`

// DBFileName is the name of the SQLite file inside an engagement directory.
const DBFileName = "engagement.db"

// Engagement is a per-run container: a directory on disk holding the SQLite
// findings DB plus per-module/per-project subdirectories for raw tool output.
type Engagement struct {
	db *sql.DB
	mu sync.Mutex
	// Dir is the engagement root directory. engagement.db lives at
	// filepath.Join(Dir, DBFileName); raw tool output lives at
	// filepath.Join(Dir, <module>, <projectID>).
	Dir string
	// OnLog is called for every LogEvent if non-nil. Used by the TUI
	// to show live sub-module progress.
	OnLog func(module, projectID, level, msg string)

	// Plaintext log sinks configured via SetLogFiles. logAll receives every
	// event; logErr receives only warn/error/fatal events. Either may be nil.
	// logMu serialises writes so concurrent module goroutines never interleave
	// partial lines. logClosers holds the underlying files to close on Close().
	logMu      sync.Mutex
	logAll     io.Writer
	logErr     io.Writer
	logClosers []io.Closer
}

// SetLogFiles opens optional plaintext log files that mirror LogEvent output,
// independent of the TUI's in-memory OnLog hook. allPath (if non-empty)
// receives every log line; errPath (if non-empty) receives only warn/error
// lines, so a run's failures land in one small, greppable file. Both are opened
// for append (so --engagement re-runs accumulate) and created if missing.
func (e *Engagement) SetLogFiles(allPath, errPath string) error {
	open := func(p string) (*os.File, error) {
		if p == "" {
			return nil, nil
		}
		if d := filepath.Dir(p); d != "" && d != "." {
			_ = os.MkdirAll(d, 0o700)
		}
		return os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	}
	f, err := open(allPath)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", allPath, err)
	}
	if f != nil {
		e.logAll = f
		e.logClosers = append(e.logClosers, f)
	}
	g, err := open(errPath)
	if err != nil {
		return fmt.Errorf("open error-log file %s: %w", errPath, err)
	}
	if g != nil {
		e.logErr = g
		e.logClosers = append(e.logClosers, g)
	}
	return nil
}

// isErrLevel reports whether a log level should land in the errors-only file.
// Module failures across the codebase are logged at "warn", so warn is included.
func isErrLevel(level string) bool {
	switch strings.ToLower(level) {
	case "warn", "warning", "error", "err", "fatal":
		return true
	}
	return false
}

func (e *Engagement) writeLogLine(module, projectID, level, msg string) {
	if e.logAll == nil && e.logErr == nil {
		return
	}
	orDash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	line := fmt.Sprintf("%s [%-5s] %s %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		strings.ToUpper(level), orDash(module), orDash(projectID), msg)
	e.logMu.Lock()
	defer e.logMu.Unlock()
	if e.logAll != nil {
		_, _ = io.WriteString(e.logAll, line)
	}
	if e.logErr != nil && isErrLevel(level) {
		_, _ = io.WriteString(e.logErr, line)
	}
}

// Open opens an engagement at the given directory. The directory is created
// if missing, and the SQLite schema is initialized.
func Open(dir string) (*Engagement, error) {
	return openEngagement(dir, false)
}

// OpenReadOnly serves an existing private engagement without initializing the
// schema, creating files or permitting database writes.
func OpenReadOnly(dir string) (*Engagement, error) {
	return openEngagement(dir, true)
}

func openEngagement(dir string, readOnly bool) (*Engagement, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.New("cannot resolve engagement directory")
	}
	// SQLite also opens journal/WAL files by pathname. Require stable ancestry:
	// non-private parents are allowed, but no links or non-sticky group/world
	// writable directory may permit another user to swap the private leaf.
	for parent := filepath.Dir(absolute); ; parent = filepath.Dir(parent) {
		info, statErr := os.Lstat(parent)
		if os.IsNotExist(statErr) {
			if parent == filepath.Dir(parent) {
				break
			}
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("engagement directory ancestors must not be symlinks or unprotected writable directories")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	if !readOnly {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	directory, err := os.Lstat(dir)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0700 {
		return nil, errors.New("engagement directory must be a private 0700 directory, not a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("cannot open engagement directory")
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(directory, opened) {
		return nil, errors.New("engagement directory changed")
	}
	// Precreate before SQLite opens: its default creation mode is otherwise
	// readable by other users until a later chmod. Never truncate an existing DB.
	if !readOnly {
		created, createErr := root.OpenFile(DBFileName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr == nil {
			if err = created.Close(); err != nil {
				return nil, err
			}
		} else if !os.IsExist(createErr) {
			return nil, errors.New("cannot create private engagement database")
		}
	}
	var database os.FileInfo
	for _, name := range []string{DBFileName, DBFileName + "-journal", DBFileName + "-wal", DBFileName + "-shm"} {
		info, statErr := root.Lstat(name)
		if name != DBFileName && os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("engagement database and sidecars must be private 0600 regular files, not symlinks")
		}
		if name == DBFileName {
			database = info
		}
	}
	dbPath, err := filepath.Abs(filepath.Join(dir, DBFileName))
	if err != nil {
		return nil, errors.New("cannot resolve engagement database path")
	}
	// Escape path characters instead of permitting a directory name containing
	// '?' or '#' to inject SQLite connection parameters. rw forbids fallback
	// creation if the private precreated file disappeared.
	mode := "mode=rw"
	if readOnly {
		mode = "mode=ro"
	}
	dsn := (&url.URL{Scheme: "file", Path: dbPath, RawQuery: mode}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	} else if err := db.Ping(); err != nil {
		db.Close()
		return nil, errors.New("cannot open existing engagement database")
	}
	// The private directory prevents other users from replacing these entries;
	// still fail closed if the caller's own concurrent operations changed them.
	currentDir, dirErr := os.Lstat(dir)
	currentDB, dbErr := root.Lstat(DBFileName)
	if dirErr != nil || dbErr != nil || !os.SameFile(directory, currentDir) || currentDir.Mode().Perm() != 0700 || !os.SameFile(database, currentDB) || !currentDB.Mode().IsRegular() || currentDB.Mode().Perm() != 0600 {
		db.Close()
		return nil, errors.New("engagement database or directory changed while opening")
	}
	return &Engagement{db: db, Dir: dir}, nil
}

func (e *Engagement) Close() error {
	for _, c := range e.logClosers {
		_ = c.Close()
	}
	return e.db.Close()
}

func (e *Engagement) DB() *sql.DB { return e.db }

// DBPath returns the absolute path to the SQLite file.
func (e *Engagement) DBPath() string { return filepath.Join(e.Dir, DBFileName) }

func (e *Engagement) SetMeta(ctx context.Context, key, value string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func (e *Engagement) GetMeta(ctx context.Context, key string) (string, bool, error) {
	row := e.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// CompletedModules returns the set of (project_id, module) pairs that have
// already finished successfully, keyed as "project|module".
func (e *Engagement) CompletedModules(ctx context.Context) (map[string]bool, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT project_id, module FROM module_runs WHERE status = 'completed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var acc, mod string
		if err := rows.Scan(&acc, &mod); err != nil {
			return nil, err
		}
		out[acc+"|"+mod] = true
	}
	return out, rows.Err()
}

func (e *Engagement) UpsertProject(ctx context.Context, projectID, alias string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO projects(project_id, alias) VALUES(?,?)
		 ON CONFLICT(project_id) DO UPDATE SET alias=excluded.alias`,
		projectID, alias)
	return err
}

func (e *Engagement) MarkProject(ctx context.Context, projectID, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`UPDATE projects SET status=?, error=?, finished_at=CASE WHEN ?='running' THEN NULL ELSE CURRENT_TIMESTAMP END,
		 started_at=COALESCE(started_at, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END)
		 WHERE project_id=?`,
		status, nullIfEmpty(errMsg), status, status, projectID)
	return err
}

func (e *Engagement) MarkModule(ctx context.Context, projectID, module, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO module_runs(project_id, module, status, error, started_at, finished_at)
		 VALUES(?, ?, ?, ?, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END,
		        CASE WHEN ? IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP END)
		 ON CONFLICT(project_id, module) DO UPDATE SET status=excluded.status, error=excluded.error,
		   finished_at=CASE WHEN excluded.status IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP ELSE module_runs.finished_at END`,
		projectID, module, status, nullIfEmpty(errMsg), status, status)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Sink implementation

func (e *Engagement) Write(ctx context.Context, f findings.Finding) error {
	detail, err := f.DetailJSON()
	if err != nil {
		return err
	}
	created := f.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = e.db.ExecContext(ctx,
		insertFindingSQL,
		f.ProjectID, f.Region, f.Module, string(f.Severity), f.ResourceName, f.Title, detail, nullIfEmpty(f.RawOutputPath), created)
	return err
}

// RawDir returns (and creates) the directory for a module's raw output for a
// given project inside the engagement dir. Path is absolute.
func (e *Engagement) RawDir(module, projectID string) (string, error) {
	if module == "" {
		return "", fmt.Errorf("module required")
	}
	parts := []string{e.Dir, module}
	if projectID != "" {
		parts = append(parts, projectID)
	}
	dir := filepath.Join(parts...)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func (e *Engagement) LogEvent(ctx context.Context, module, projectID, level, msg string) error {
	if e.OnLog != nil {
		e.OnLog(module, projectID, level, msg)
	}
	e.writeLogLine(module, projectID, level, msg)
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO logs(project_id, module, level, msg, created_at) VALUES(?,?,?,?,?)`,
		nullIfEmpty(projectID), nullIfEmpty(module), level, msg, time.Now().UTC())
	return err
}
