package report

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
)

func exportServerEngagement(t *testing.T) *engagement.Engagement {
	t.Helper()
	created, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := created.DB().Begin()
	if err != nil {
		created.Close()
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO findings(project_id,module,severity,resource_name,title,detail_json,created_at) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		created.Close()
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		resource := fmt.Sprintf("//storage.googleapis.com/buckets/bucket-%02d", i%25)
		module, severity := "public_iam", "high"
		if i%2 == 1 {
			module, severity = "configuration_plaintext", "info"
		}
		detail, err := json.Marshal(map[string]any{"evidence": map[string]any{"value": fmt.Sprintf("SYNTHETIC_ACTUAL_VALUE_%03d", i), "source": resource, "field": "PASSWORD"}, "credential_validation_performed": false})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := statement.Exec(fmt.Sprintf("project-%d", i%2), module, severity, resource, fmt.Sprintf("Native finding %03d", i), string(detail), "2026-10-06T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	statement.Close()
	if err := tx.Commit(); err != nil {
		created.Close()
		t.Fatal(err)
	}
	dir := created.Dir
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := engagement.OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { existing.Close() })
	return existing
}

func checkPrivateDownload(t *testing.T, w *httptest.ResponseRecorder, contentType, filename string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(w.Header())
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), contentType) || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") || !strings.Contains(w.Header().Get("Content-Disposition"), filename) {
		t.Fatal(w.Header())
	}
}

func TestExportExistingDBIncludesAllPagesAndActualValues(t *testing.T) {
	h := Handler(exportServerEngagement(t))
	w := serveReportRequest(h, "GET", "/api/export/json")
	checkPrivateDownload(t, w, "application/json", ".json")
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 500 {
		t.Fatal("download truncated to current page", len(rows))
	}
	for _, sentinel := range []string{"SYNTHETIC_ACTUAL_VALUE_000", "SYNTHETIC_ACTUAL_VALUE_249", "SYNTHETIC_ACTUAL_VALUE_499"} {
		if !strings.Contains(w.Body.String(), sentinel) {
			t.Fatal("missing full value", sentinel)
		}
	}
	w = serveReportRequest(h, "GET", "/api/export/assets")
	checkPrivateDownload(t, w, "text/plain", ".txt")
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 25 {
		t.Fatal("assets not deduplicated", len(lines), w.Body.String())
	}
	seen := map[string]bool{}
	for _, line := range lines {
		if !strings.HasPrefix(line, "//storage.googleapis.com/buckets/bucket-") || seen[line] {
			t.Fatal(line)
		}
		seen[line] = true
	}
	if strings.Contains(w.Body.String(), "SYNTHETIC_ACTUAL_VALUE") || strings.Contains(w.Body.String(), "PASSWORD") {
		t.Fatal("asset export included credential evidence")
	}
}

func TestExportFiltersMatchPaginatedReportSelection(t *testing.T) {
	h := Handler(exportServerEngagement(t))
	for _, tc := range []struct {
		query         string
		count, assets int
	}{
		{"category=secrets", 250, 25}, {"module=public_iam", 250, 25},
		{"project=project-1", 250, 25}, {"severity=info", 250, 25},
		{"q=bucket-07", 20, 1}, {"category=secrets&q=bucket-07", 10, 1},
		{"category=secrets&module=public_iam", 0, 0}, {"q=SYNTHETIC_ACTUAL_VALUE", 0, 0},
	} {
		w := serveReportRequest(h, "GET", "/api/export/json?"+tc.query)
		checkPrivateDownload(t, w, "application/json", ".json")
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != tc.count {
			t.Fatal(tc, len(rows))
		}
		w = serveReportRequest(h, "GET", "/api/export/assets?"+tc.query)
		checkPrivateDownload(t, w, "text/plain", ".txt")
		text := strings.TrimSpace(w.Body.String())
		count := 0
		if text != "" {
			count = len(strings.Split(text, "\n"))
		}
		if count != tc.assets {
			t.Fatal(tc, count, text)
		}
	}
}

func TestExportRejectsInvalidRequestsAndCrossOrigin(t *testing.T) {
	h := Handler(exportServerEngagement(t))
	for _, route := range []string{"/api/export/json", "/api/export/assets"} {
		for _, query := range []string{"page=1", "page_size=50", "unknown=1", "category=unknown", "severity=unknown", "project=a&project=b", "q=%ZZ", "q=%00", "filename=../../engagement.db", "path=secret-hits/whatever"} {
			w := serveReportRequest(h, "GET", route+"?"+query)
			if w.Code != http.StatusBadRequest {
				t.Fatal(route, query, w.Code)
			}
			if strings.Contains(w.Body.String(), "SYNTHETIC_ACTUAL_VALUE") {
				t.Fatal("invalid export leaked values")
			}
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			if w := serveReportRequest(h, method, route); w.Code != http.StatusMethodNotAllowed {
				t.Fatal(method, route, w.Code)
			}
		}
		req := httptest.NewRequest("GET", "http://127.0.0.1:8080"+route, nil)
		req.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatal(route, w.Code)
		}
	}
	for _, path := range []string{"/api/export/engagement.db", "/api/export/../../engagement.db", "/api/export/%6ason", "/raw/findings.json", "/findings.json"} {
		if w := serveReportRequest(h, "GET", path); w.Code != http.StatusNotFound {
			t.Fatal(path, w.Code)
		}
	}
}

func TestAssetDownloadUsesReviewedProvenanceNotCredentialFields(t *testing.T) {
	created, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	for _, tc := range []struct{ module, resource, detail string }{
		{"configuration_plaintext", "//gcpbuster.googleapis.com/capturedConfiguration/opaque", `{"evidence":{"source":"//run.googleapis.com/projects/demo/locations/us-central1/services/app","value":"SYNTHETIC_ACTUAL_TOKEN","pull_command":"curl --header Authorization:SYNTHETIC_ACTUAL_TOKEN"}}`},
		{"secrets_scan", "//gcpbuster.googleapis.com/secretScan/opaque", `{"evidence":{"source":"//run.googleapis.com/projects/demo/locations/us-central1/services/app","match":"SYNTHETIC_ACTUAL_TOKEN"}}`},
		{"public_iam", "//storage.googleapis.com/buckets/legitimate/permission-analysis/0123456789abcdef01234567", `{}`},
		{"iam_permissions", "projects/demo/permission-analysis/0123456789abcdef01234567", `{"asset_type":"gcpbuster.googleapis.com/PermissionGrant","evidence":{"resource":"//storage.googleapis.com/buckets/legitimate"}}`},
		{"secrets_scan", "", `{"evidence":{"source":"https://evil.example/token=SYNTHETIC_ACTUAL_TOKEN","value":"//storage.googleapis.com/buckets/not-an-asset"}}`},
		{"configuration_plaintext", "invalid\nresource", `{"evidence":{"source":"SYNTHETIC_ACTUAL_TOKEN","value":"SYNTHETIC_ACTUAL_TOKEN"}}`},
		{"unknown_module", "//gcpbuster.googleapis.com/findings/opaque", `{"evidence":{"source":"//storage.googleapis.com/buckets/not-reviewed","value":"SYNTHETIC_ACTUAL_TOKEN"}}`},
	} {
		if _, err := created.DB().Exec(`INSERT INTO findings(project_id,module,severity,resource_name,title,detail_json,raw_output_path,created_at) VALUES('demo',?,'info',?,'SYNTHETIC_ACTUAL_TOKEN',?,'javascript:alert(1)','2026-10-06T00:00:00Z')`, tc.module, tc.resource, tc.detail); err != nil {
			t.Fatal(err)
		}
	}
	w := serveReportRequest(Handler(created), "GET", "/api/export/assets")
	checkPrivateDownload(t, w, "text/plain", ".txt")
	want := "//run.googleapis.com/projects/demo/locations/us-central1/services/app\n//storage.googleapis.com/buckets/legitimate\n"
	if w.Body.String() != want {
		t.Fatal(w.Body.String())
	}
	w = serveReportRequest(Handler(created), "GET", "/api/export/json")
	checkPrivateDownload(t, w, "application/json", ".json")
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Fatal(len(rows))
	}
	for _, row := range rows {
		if _, exists := row["raw_output_path"]; exists {
			t.Fatal("unsafe source path exported", row)
		}
	}
}
