package report

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
)

//go:embed index.html
var page string
var tmpl = template.Must(template.New("report").Parse(page))

type Row struct {
	Project       string `json:"project"`
	Module        string `json:"module"`
	Severity      string `json:"severity"`
	Resource      string `json:"resource"`
	Title         string `json:"title"`
	Detail        string `json:"detail"`
	RawOutputPath string `json:"raw_output_path,omitempty"`
}
type Run struct{ Project, Module, Status, Error string }
type Section struct {
	Key, Label string
	Findings   []Row
}
type Data struct {
	Sections []Section
	Runs     []Run
	Coverage string
	Count    int
}

func Read(db *sql.DB) (Data, []Row, error) {
	var d Data
	all := []Row{}
	rows, err := db.Query(`SELECT project_id,module,severity,resource_name,title,detail_json,COALESCE(raw_output_path,'') FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,id`)
	if err != nil {
		return d, nil, err
	}
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Project, &r.Module, &r.Severity, &r.Resource, &r.Title, &r.Detail, &r.RawOutputPath); err != nil {
			rows.Close()
			return d, nil, err
		}
		if !engagement.ValidSecretArtifactPath(r.RawOutputPath) {
			r.RawOutputPath = ""
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, nil, err
	}
	for _, cat := range checks.Categories {
		sec := Section{Key: cat.Key, Label: cat.Label}
		for _, r := range all {
			if checks.CategoryOf(r.Module) == cat.Key {
				sec.Findings = append(sec.Findings, r)
			}
		}
		d.Sections = append(d.Sections, sec)
	}
	runs, err := db.Query(`SELECT project_id,module,status,COALESCE(error,'') FROM module_runs ORDER BY project_id,module`)
	if err != nil {
		return d, nil, err
	}
	for runs.Next() {
		var r Run
		if err := runs.Scan(&r.Project, &r.Module, &r.Status, &r.Error); err != nil {
			runs.Close()
			return d, nil, err
		}
		d.Runs = append(d.Runs, r)
	}
	err = runs.Err()
	runs.Close()
	if err != nil {
		return d, nil, err
	}
	err = db.QueryRow(`SELECT value FROM meta WHERE key='coverage'`).Scan(&d.Coverage)
	if err != nil && err != sql.ErrNoRows {
		return d, nil, err
	}
	d.Count = len(all)
	return d, all, nil
}
func Export(e *engagement.Engagement) error {
	d, rows, err := Read(e.DB())
	if err != nil {
		return err
	}
	if err := privateExport(e.Dir, "report.html", func(w io.Writer) error { return tmpl.Execute(w, d) }); err != nil {
		return err
	}
	return privateExport(e.Dir, "findings.json", func(w io.Writer) error { return json.NewEncoder(w).Encode(rows) })
}

// Atomic replacement gives pre-existing exports private modes without following
// output symlinks or temporarily truncating a world-readable report in place.
func privateExport(dir, name string, write func(io.Writer) error) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open report directory")
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return errors.New("invalid report output file")
	} else if err != nil && !os.IsNotExist(err) {
		return errors.New("cannot inspect report output")
	}
	tmp := ".report-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create private report")
	}
	defer func() { f.Close(); _ = root.Remove(tmp) }()
	if err = write(f); err != nil {
		return errors.New("cannot render report")
	}
	if err = f.Sync(); err != nil {
		return errors.New("cannot sync report")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close report")
	}
	if err = root.Rename(tmp, name); err != nil {
		return errors.New("cannot publish report")
	}
	return nil
}
func Handler(e *engagement.Engagement) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/secret-hits/") {
			relative := strings.TrimPrefix(r.URL.Path, "/")
			var referenced int
			if !engagement.ValidSecretArtifactPath(relative) || r.URL.RawPath != "" || r.URL.RawQuery != "" {
				http.NotFound(w, r)
				return
			}
			if err := e.DB().QueryRowContext(r.Context(), `SELECT COUNT(*) FROM findings WHERE raw_output_path=?`, relative).Scan(&referenced); err != nil || referenced == 0 {
				http.NotFound(w, r)
				return
			}
			f, err := e.OpenSecretArtifact(relative)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer f.Close()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(relative)+`"`)
			_, _ = io.Copy(w, io.LimitReader(f, engagement.SecretArtifactMaxBytes))
			return
		}
		d, rows, err := Read(e.DB())
		if err != nil {
			http.Error(w, "Cannot read engagement", 500)
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = tmpl.Execute(w, d)
		case "/api/findings":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rows)
		default:
			http.NotFound(w, r)
		}
	})
}
func Serve(addr string, e *engagement.Engagement) error {
	s := &http.Server{Addr: addr, Handler: Handler(e), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return s.ListenAndServe()
}
func Render(w io.Writer, d Data) error { return tmpl.Execute(w, d) }
