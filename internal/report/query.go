package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
)

type BriefRow struct {
	ID               int64  `json:"id"`
	Category         string `json:"category"`
	Project          string `json:"project"`
	Module           string `json:"module"`
	Severity         string `json:"severity"`
	Resource         string `json:"resource"`
	ResourceName     string `json:"resource_name"`
	ResourceIdentity string `json:"resource_identity"`
	Title            string `json:"title"`
	RawOutputPath    string `json:"raw_output_path,omitempty"`
}
type QueryRow struct {
	Row
	ID       int64  `json:"id"`
	Category string `json:"category"`
}
type queryPage struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

func pagination(q url.Values) (queryPage, error) {
	p := queryPage{Page: 1, PageSize: 50}
	for _, key := range []string{"page", "page_size"} {
		if len(q[key]) > 1 {
			return p, errors.New("duplicate pagination")
		}
		if raw := q.Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1000000 {
				return p, errors.New("invalid pagination")
			}
			if key == "page" {
				p.Page = n
			} else {
				p.PageSize = n
			}
		}
	}
	if p.PageSize > 200 {
		return p, errors.New("page_size exceeds 200")
	}
	return p, nil
}

func findingFilter(q url.Values) (string, []any, error) {
	parts := []string{"1=1"}
	var args []any
	for _, key := range []string{"category", "module", "project", "severity", "q"} {
		value := q.Get(key)
		if len(q[key]) > 1 || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
			return "", nil, errors.New("invalid filter")
		}
		if value == "" {
			continue
		}
		switch key {
		case "category":
			valid := false
			for _, cat := range checks.Categories {
				if cat.Key == value {
					valid = true
				}
			}
			if !valid {
				return "", nil, errors.New("invalid category")
			}
			var slots []string
			for _, check := range checks.All {
				if check.Category == value {
					slots = append(slots, "?")
					args = append(args, check.ID)
				}
			}
			if value == "best_practices" {
				slots = append(slots, "?")
				args = append(args, "scoutsuite")
			}
			parts = append(parts, "module IN ("+strings.Join(slots, ",")+")")
		case "module", "project", "severity":
			column := map[string]string{"module": "module", "project": "project_id", "severity": "severity"}[key]
			if key == "severity" && value != "critical" && value != "high" && value != "medium" && value != "low" && value != "info" {
				return "", nil, errors.New("invalid severity")
			}
			parts = append(parts, column+"=?")
			args = append(args, value)
		case "q":
			// Search visible metadata, never credential-containing detail_json.
			escaped := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(value)
			parts = append(parts, `(resource_name LIKE ? ESCAPE '\' OR title LIKE ? ESCAPE '\' OR project_id LIKE ? ESCAPE '\' OR module LIKE ? ESCAPE '\')`)
			for i := 0; i < 4; i++ {
				args = append(args, "%"+escaped+"%")
			}
		}
	}
	return strings.Join(parts, " AND "), args, nil
}

// APIHandler reads the existing engagement database directly. List endpoints
// fetch bounded pages and omit large secret evidence until a detail is opened.
func APIHandler(db *sql.DB) http.Handler {
	exports := ExportHandler(db)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		if len(r.URL.RawQuery) > 8192 {
			http.Error(w, "query too long", 400)
			return
		}
		if r.URL.Path == "/api/export/json" || r.URL.Path == "/api/export/assets" {
			exports.ServeHTTP(w, r)
			return
		}
		q, parseErr := url.ParseQuery(r.URL.RawQuery)
		if parseErr != nil {
			http.Error(w, "invalid query", 400)
			return
		}
		allowed := map[string]bool{}
		switch r.URL.Path {
		case "/api/findings", "/api/summary":
			for _, key := range []string{"category", "module", "project", "severity", "q"} {
				allowed[key] = true
			}
		case "/api/runs":
			for _, key := range []string{"project", "module", "status"} {
				allowed[key] = true
			}
		}
		if r.URL.Path == "/api/findings" || r.URL.Path == "/api/runs" || r.URL.Path == "/api/coverage" {
			allowed["page"] = true
			allowed["page_size"] = true
		}
		for key, values := range q {
			if !allowed[key] || len(values) != 1 || len(values[0]) > 1024 || !utf8.ValidString(values[0]) || strings.ContainsAny(values[0], "\x00\r\n") {
				http.Error(w, "invalid query", 400)
				return
			}
		}
		var result any
		var err error
		switch {
		case r.URL.Path == "/api/findings":
			result, err = queryFindings(r.Context(), db, q)
		case r.URL.Path == "/api/summary":
			result, err = querySummary(r.Context(), db, q)
		case r.URL.Path == "/api/runs":
			result, err = queryRuns(r.Context(), db, q)
		case r.URL.Path == "/api/coverage":
			result, err = queryCoverage(r.Context(), db, q)
		case strings.HasPrefix(r.URL.Path, "/api/findings/"):
			id, parseErr := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/findings/"), 10, 64)
			if parseErr != nil || id < 1 || strconv.FormatInt(id, 10) != strings.TrimPrefix(r.URL.Path, "/api/findings/") || r.URL.RawQuery != "" {
				http.Error(w, "invalid finding ID", 400)
				return
			}
			var row QueryRow
			err = db.QueryRowContext(r.Context(), `SELECT id,project_id,module,severity,resource_name,title,detail_json,COALESCE(raw_output_path,'') FROM findings WHERE id=?`, id).Scan(&row.ID, &row.Project, &row.Module, &row.Severity, &row.Resource, &row.Title, &row.Detail, &row.RawOutputPath)
			row.Category = checks.CategoryOf(row.Module)
			row.ResourceName, row.ResourceIdentity = resourceMetadataFromDetail(row.Resource, row.Module, row.Detail)
			if !engagement.ValidSecretArtifactPath(row.RawOutputPath) {
				row.RawOutputPath = ""
			}
			result = row
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
			} else if errors.Is(err, errBadQuery) {
				http.Error(w, "invalid query", 400)
			} else {
				http.Error(w, "report query failed", 500)
			}
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
}

var errBadQuery = errors.New("invalid query")

func queryFindings(ctx context.Context, db *sql.DB, q url.Values) (any, error) {
	p, err := pagination(q)
	if err != nil {
		return nil, errBadQuery
	}
	where, args, err := findingFilter(q)
	if err != nil {
		return nil, errBadQuery
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE "+where, args...).Scan(&p.Total); err != nil {
		return nil, err
	}
	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	// Materialize only selected IDs before inspecting provenance JSON. Sorting
	// a large engagement never parses every finding's potentially large detail.
	rows, err := db.QueryContext(ctx, `WITH selected AS MATERIALIZED (SELECT id FROM findings WHERE `+where+` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,id LIMIT ? OFFSET ?) SELECT f.id,project_id,module,severity,resource_name,title,COALESCE(raw_output_path,''),COALESCE(`+resourceCandidateSQL+`,'') FROM selected JOIN findings f ON f.id=selected.id ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,f.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BriefRow{}
	for rows.Next() {
		var row BriefRow
		var provenance string
		if err := rows.Scan(&row.ID, &row.Project, &row.Module, &row.Severity, &row.Resource, &row.Title, &row.RawOutputPath, &provenance); err != nil {
			return nil, err
		}
		row.Category = checks.CategoryOf(row.Module)
		row.ResourceName, row.ResourceIdentity = resourceMetadata(row.Resource, provenance)
		if !engagement.ValidSecretArtifactPath(row.RawOutputPath) {
			row.RawOutputPath = ""
		}
		items = append(items, row)
	}
	return struct {
		queryPage
		Findings []BriefRow `json:"findings"`
	}{p, items}, rows.Err()
}

type categoryCount struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}
type moduleCount struct {
	Module   string `json:"module"`
	Category string `json:"category"`
	Count    int    `json:"count"`
}
type summaryResult struct {
	Total      int             `json:"total"`
	Categories []categoryCount `json:"categories"`
	Modules    []moduleCount   `json:"modules"`
	Projects   []string        `json:"projects"`
	Severity   map[string]int  `json:"severity"`
}

func querySummary(ctx context.Context, db *sql.DB, q url.Values) (any, error) {
	where, args, err := findingFilter(q)
	if err != nil {
		return nil, errBadQuery
	}
	out := summaryResult{Modules: []moduleCount{}, Projects: []string{}, Severity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
	counts := map[string]int{}
	rows, err := db.QueryContext(ctx, "SELECT module,COUNT(*) FROM findings WHERE "+where+" GROUP BY module ORDER BY module", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m moduleCount
		if err := rows.Scan(&m.Module, &m.Count); err != nil {
			rows.Close()
			return nil, err
		}
		m.Category = checks.CategoryOf(m.Module)
		out.Modules = append(out.Modules, m)
		counts[m.Category] += m.Count
		out.Total += m.Count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, cat := range checks.Categories {
		out.Categories = append(out.Categories, categoryCount{cat.Key, cat.Label, counts[cat.Key]})
	}
	rows, err = db.QueryContext(ctx, "SELECT severity,COUNT(*) FROM findings WHERE "+where+" GROUP BY severity", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var severity string
		var n int
		if err := rows.Scan(&severity, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.Severity[severity] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = db.QueryContext(ctx, "SELECT DISTINCT project_id FROM findings WHERE "+where+" ORDER BY project_id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var project string
		if err := rows.Scan(&project); err != nil {
			return nil, err
		}
		out.Projects = append(out.Projects, project)
	}
	return out, rows.Err()
}

func queryRuns(ctx context.Context, db *sql.DB, q url.Values) (any, error) {
	p, err := pagination(q)
	if err != nil {
		return nil, errBadQuery
	}
	where := []string{"1=1"}
	var args []any
	for _, key := range []string{"project", "module", "status"} {
		if value := q.Get(key); value != "" {
			if len(value) > 1024 || strings.ContainsRune(value, 0) {
				return nil, errBadQuery
			}
			column := map[string]string{"project": "project_id", "module": "module", "status": "status"}[key]
			where = append(where, column+"=?")
			args = append(args, value)
		}
	}
	filter := strings.Join(where, " AND ")
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM module_runs WHERE "+filter, args...).Scan(&p.Total); err != nil {
		return nil, err
	}
	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	rows, err := db.QueryContext(ctx, "SELECT project_id,module,status,COALESCE(error,'') FROM module_runs WHERE "+filter+" ORDER BY project_id,module LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type runRow struct {
		Project string `json:"project"`
		Module  string `json:"module"`
		Status  string `json:"status"`
		Error   string `json:"error"`
	}
	items := []runRow{}
	for rows.Next() {
		var row runRow
		if err := rows.Scan(&row.Project, &row.Module, &row.Status, &row.Error); err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return struct {
		queryPage
		Runs []runRow `json:"runs"`
	}{p, items}, rows.Err()
}

func queryCoverage(ctx context.Context, db *sql.DB, q url.Values) (any, error) {
	p, err := pagination(q)
	if err != nil {
		return nil, errBadQuery
	}
	// JSON1 paginates the existing meta array inside SQLite; no rescan or schema
	// migration is needed and Go never materializes the complete coverage blob.
	const source = ` FROM json_each(COALESCE((SELECT value FROM meta WHERE key='coverage'),'[]'))`
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*)"+source).Scan(&p.Total); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(json_extract(value,'$.source'),''),COALESCE(json_extract(value,'$.status'),''),COALESCE(json_extract(value,'$.count'),0),COALESCE(json_extract(value,'$.error'),'')`+source+` ORDER BY CAST(key AS INTEGER) LIMIT ? OFFSET ?`, p.PageSize, (p.Page-1)*p.PageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type coverageRow struct {
		Source string `json:"source"`
		Status string `json:"status"`
		Count  int    `json:"count"`
		Error  string `json:"error"`
	}
	items := []coverageRow{}
	for rows.Next() {
		var row coverageRow
		if err := rows.Scan(&row.Source, &row.Status, &row.Count, &row.Error); err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return struct {
		queryPage
		Coverage []coverageRow `json:"coverage"`
	}{p, items}, rows.Err()
}
