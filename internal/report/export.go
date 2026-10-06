package report

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
)

type exportRow struct {
	BriefRow
	Region    string          `json:"region"`
	CreatedAt any             `json:"created_at"`
	Detail    json.RawMessage `json:"detail"`
}

// ExportHandler exports every matching finding, independently of the current
// UI page. A private temporary spool avoids reporting success for an incomplete
// SQL/JSON export; only the finished file is streamed to the client. It is
// deleted on every exit and never becomes a report/source artifact.
func ExportHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if r.URL.RawPath != "" || (r.URL.Path != "/api/export/json" && r.URL.Path != "/api/export/assets") {
			http.NotFound(w, r)
			return
		}
		if len(r.URL.RawQuery) > 8192 {
			http.Error(w, "invalid query", 400)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid query", 400)
			return
		}
		for key, values := range q {
			if key != "category" && key != "module" && key != "project" && key != "severity" && key != "q" || len(values) != 1 {
				http.Error(w, "invalid query", 400)
				return
			}
		}
		where, args, err := findingFilter(q)
		if err != nil {
			http.Error(w, "invalid query", 400)
			return
		}
		spool, err := os.CreateTemp("", "gcpbuster-export-*")
		if err != nil {
			http.Error(w, "cannot prepare export", 500)
			return
		}
		defer func() { spool.Close(); os.Remove(spool.Name()) }()
		buffer := bufio.NewWriterSize(spool, 64<<10)
		jsonExport := r.URL.Path == "/api/export/json"
		if jsonExport {
			err = exportJSON(r.Context(), db, buffer, where, args)
		} else {
			err = exportAssets(r.Context(), db, buffer, where, args)
		}
		if err == nil {
			err = buffer.Flush()
		}
		if err == nil {
			_, err = spool.Seek(0, io.SeekStart)
		}
		if err != nil {
			http.Error(w, "cannot prepare export", 500)
			return
		}
		info, err := spool.Stat()
		if err != nil {
			http.Error(w, "cannot prepare export", 500)
			return
		}
		selection := q.Get("module")
		if selection == "" {
			selection = q.Get("category")
		}
		if selection == "" || len(selection) > 100 || strings.ContainsAny(selection, "\r\n") || strings.IndexFunc(selection, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
		}) >= 0 {
			selection = "all"
		}
		filename := "gcpbuster-" + selection + "-assets.txt"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if jsonExport {
			filename = "gcpbuster-" + selection + ".json"
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		_, _ = io.Copy(w, spool)
	})
}

func exportJSON(ctx context.Context, db *sql.DB, w io.Writer, where string, args []any) error {
	rows, err := db.QueryContext(ctx, `SELECT id,project_id,module,severity,resource_name,title,detail_json,COALESCE(raw_output_path,''),region,created_at FROM findings WHERE `+where+` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,id`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if _, err = io.WriteString(w, "["); err != nil {
		return err
	}
	first := true
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var row exportRow
		var detail string
		if err := rows.Scan(&row.ID, &row.Project, &row.Module, &row.Severity, &row.Resource, &row.Title, &detail, &row.RawOutputPath, &row.Region, &row.CreatedAt); err != nil {
			return err
		}
		if !json.Valid([]byte(detail)) {
			return errors.New("invalid stored detail")
		}
		row.Detail = json.RawMessage(detail)
		row.Category = checks.CategoryOf(row.Module)
		row.ResourceName, row.ResourceIdentity = resourceMetadataFromDetail(row.Resource, row.Module, detail)
		if !engagement.ValidSecretArtifactPath(row.RawOutputPath) {
			row.RawOutputPath = ""
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := json.NewEncoder(w).Encode(row); err != nil {
			return err
		}
		first = false
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "]\n")
	return err
}

func validExportAsset(value string) bool {
	if value == "" || len(value) > 8192 || !utf8.ValidString(value) || strings.HasPrefix(value, "//gcpbuster.googleapis.com/") {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	// Preserve Unicode/spaces in resource paths without accepting a bare token
	// or an executable URI as an asset identifier.
	for _, prefix := range []string{"projects/", "folders/", "organizations/", "workspace/"} {
		if strings.HasPrefix(value, prefix) {
			return len(value) > len(prefix)
		}
	}
	if strings.HasPrefix(value, "//") {
		host, path, ok := strings.Cut(strings.TrimPrefix(value, "//"), "/")
		return ok && path != "" && strings.HasSuffix(host, ".googleapis.com") && validExportHost(host)
	}
	if strings.HasPrefix(value, "gs://") {
		host := strings.SplitN(strings.TrimPrefix(value, "gs://"), "/", 2)[0]
		return validExportHost(host)
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && validExportHost(u.Hostname()) && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func validExportHost(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func exportAssets(ctx context.Context, db *sql.DB, w io.Writer, where string, args []any) error {
	// Only reviewed provenance fields are asset candidates. Never use an actual
	// match/value/token, the finding title, an arbitrary endpoint, or refetch text.
	// JSON inspection is limited to the exact synthetic source/permission types.
	const sourceExpression = `CASE
 WHEN module IN ('secrets_scan','configuration_plaintext') AND json_valid(detail_json) AND json_type(detail_json,'$.evidence.source')='text' AND (json_extract(detail_json,'$.evidence.source') LIKE '//%.googleapis.com/%' OR json_extract(detail_json,'$.evidence.source') LIKE 'projects/%' OR json_extract(detail_json,'$.evidence.source') LIKE 'folders/%' OR json_extract(detail_json,'$.evidence.source') LIKE 'organizations/%' OR json_extract(detail_json,'$.evidence.source') LIKE 'workspace/%' OR json_extract(detail_json,'$.evidence.source') LIKE 'gs://%') THEN json_extract(detail_json,'$.evidence.source')
 WHEN json_valid(detail_json) AND json_extract(detail_json,'$.asset_type')='gcpbuster.googleapis.com/PermissionGrant' AND json_type(detail_json,'$.evidence.resource')='text' AND (json_extract(detail_json,'$.evidence.resource') LIKE '//%.googleapis.com/%' OR json_extract(detail_json,'$.evidence.resource') LIKE 'projects/%' OR json_extract(detail_json,'$.evidence.resource') LIKE 'folders/%' OR json_extract(detail_json,'$.evidence.resource') LIKE 'organizations/%' OR json_extract(detail_json,'$.evidence.resource') LIKE 'workspace/%' OR json_extract(detail_json,'$.evidence.resource') LIKE 'gs://%') THEN json_extract(detail_json,'$.evidence.resource')
 ELSE resource_name END`
	// The generated binding suffix is precisely /permission-analysis/24 hex.
	// Normalize it in SQL before DISTINCT so duplicate underlying resources do
	// not need an unbounded in-memory set. SQLite handles sorting/deduplication.
	const normalized = `CASE WHEN length(candidate)>=45 AND substr(candidate,-45,21)='/permission-analysis/' AND substr(candidate,-24) NOT GLOB '*[^0-9a-f]*' THEN substr(candidate,1,length(candidate)-45) ELSE candidate END`
	rows, err := db.QueryContext(ctx, `WITH candidates AS (SELECT `+sourceExpression+` AS candidate FROM findings WHERE `+where+`), assets AS (SELECT `+normalized+` AS asset FROM candidates) SELECT DISTINCT asset FROM assets WHERE asset<>'' ORDER BY asset`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var asset string
		if err := rows.Scan(&asset); err != nil {
			return err
		}
		if validExportAsset(asset) {
			if _, err := io.WriteString(w, asset+"\n"); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}
