package report

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
)

func largeServerEngagement(t *testing.T) *engagement.Engagement {
	t.Helper()
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	tx, err := e.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT INTO findings(project_id,module,severity,resource_name,title,detail_json,created_at) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for i := 0; i < 20000; i++ {
		module, severity := "public_iam", "high"
		if i%2 == 1 {
			module, severity = "configuration_plaintext", "info"
		}
		detail := fmt.Sprintf(`{"evidence":{"value":"FULL_PRIVATE_VALUE_%d"},"untrusted":"<script>alert('fixture')</script>","padding":"%s"}`, i, strings.Repeat("x", 1024))
		if _, err := statement.Exec(fmt.Sprintf("project-%d", i%3), module, severity, fmt.Sprintf("resource-%d", i), fmt.Sprintf("<img src=x onerror=alert(1)> finding %d", i), detail, "2026-10-06T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return e
}

func serveReportRequest(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, "http://127.0.0.1:8080"+path, nil))
	return w
}

func TestServerShellDoesNotEmbedLargeEngagement(t *testing.T) {
	created := largeServerEngagement(t)
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := engagement.OpenReadOnly(created.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	h := Handler(existing)
	w := serveReportRequest(h, "GET", "/")
	if w.Code != http.StatusOK || len(w.Body.Bytes()) > 256<<10 {
		t.Fatal(w.Code, len(w.Body.Bytes()))
	}
	for _, private := range []string{"FULL_PRIVATE_VALUE_", "resource-19999", "<img src=x onerror", "<script>alert('fixture')"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("shell embedded finding payload", private)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(w.Header())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatal("API fetch blocked by CSP", w.Header())
	}
	page := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings"))
	if page["total"] != float64(20000) {
		t.Fatal(page)
	}
	if _, err := existing.DB().Exec(`INSERT INTO meta(key,value) VALUES('unexpected-report-write','bad')`); err == nil {
		t.Fatal("report DB is writable")
	}
}

func TestReportRejectsCrossOriginAPIAndArtifactAccess(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	h := Handler(e)
	for _, path := range []string{"/", "/api/findings", "/api/summary", "/secret-hits/00000000000000000000000000000000.txt"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8080"+path, nil)
		req.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatal(path, w.Code)
		}
	}
	for _, origin := range []string{"http://127.0.0.1:8080", ""} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatal(origin, w.Code)
		}
	}
	for _, origin := range []string{"https://127.0.0.1:8080", "null", "http://127.0.0.1:8081", "http://user@127.0.0.1:8080", "http://127.0.0.1:8080/"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/findings", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatal(origin, w.Code)
		}
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/findings", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}

func TestReportServerRefusesNonLoopbackBinding(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "192.0.2.1:8080", "[::]:8080", "evil.example:8080", "not-an-address"} {
		// Validation must happen before constructing handlers or opening a socket.
		if err := ServeContext(context.Background(), addr, nil); err == nil {
			t.Fatal(addr)
		}
	}
}

func decodeServerJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal(w.Header())
	}
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLargeServerFindingPaginationFiltersAndLazyDetail(t *testing.T) {
	h := Handler(largeServerEngagement(t))
	first := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings?page_size=37"))
	if first["total"] != float64(20000) || first["page"] != float64(1) || first["page_size"] != float64(37) {
		t.Fatal(first)
	}
	items := first["findings"].([]any)
	if len(items) != 37 {
		t.Fatal(len(items))
	}
	seen := map[float64]bool{}
	for _, raw := range items {
		row := raw.(map[string]any)
		seen[row["id"].(float64)] = true
		if _, exists := row["detail"]; exists {
			t.Fatal("list loaded detail", row)
		}
	}
	second := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings?page=2&page_size=37"))
	for _, raw := range second["findings"].([]any) {
		if seen[raw.(map[string]any)["id"].(float64)] {
			t.Fatal("page overlap")
		}
	}
	empty := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings?page=101&page_size=200"))
	if empty["total"] != float64(20000) || len(empty["findings"].([]any)) != 0 {
		t.Fatal(empty)
	}
	for _, tc := range []struct {
		query string
		total int
	}{
		{"category=secrets", 10000}, {"module=public_iam", 10000}, {"severity=info", 10000},
		{"project=project-1", 6667}, {"category=secrets&project=project-1", 3334},
		{"q=resource-19999", 1}, {"q=FULL_PRIVATE_VALUE_19999", 0}, {"q=%25", 0},
		{"module=%27%20OR%201%3D1--", 0},
	} {
		w := serveReportRequest(h, "GET", "/api/findings?"+tc.query)
		data := decodeServerJSON(t, w)
		if data["total"] != float64(tc.total) || len(data["findings"].([]any)) > 50 {
			t.Fatal(tc, data)
		}
		if strings.Contains(w.Body.String(), "FULL_PRIVATE_VALUE_") {
			t.Fatal("list leaked detail")
		}
	}
	id := int64(items[0].(map[string]any)["id"].(float64))
	w := serveReportRequest(h, "GET", "/api/findings/"+strconv.FormatInt(id, 10))
	detail := decodeServerJSON(t, w)
	if !strings.Contains(detail["detail"].(string), "FULL_PRIVATE_VALUE_") {
		t.Fatal(detail)
	}
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<img src=x") {
		t.Fatal("JSON not HTML escaped")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Header())
	}
	summary := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/summary"))
	if summary["total"] != float64(20000) || len(summary["categories"].([]any)) != 4 || len(summary["projects"].([]any)) != 3 {
		t.Fatal(summary)
	}
}

func TestServerAPIRoutingAndBadQueries(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	h := Handler(e)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/api/findings", 405}, {"DELETE", "/api/findings/1", 405},
		{"GET", "/api/findings?page=0", 400}, {"GET", "/api/findings?page=-1", 400},
		{"GET", "/api/findings?page_size=201", 400}, {"GET", "/api/findings?page_size=0", 400},
		{"GET", "/api/findings?page=1&page=2", 400}, {"GET", "/api/findings?unknown=1", 400},
		{"GET", "/api/findings?category=invalid", 400}, {"GET", "/api/findings?severity=invalid", 400},
		{"GET", "/api/findings?module=a&module=b", 400}, {"GET", "/api/findings?q=%00", 400},
		{"GET", "/api/findings?q=%ZZ", 400}, {"GET", "/api/findings/1?download=1", 400},
		{"GET", "/api/findings/0", 400}, {"GET", "/api/findings/00001", 400},
		{"GET", "/api/findings/999999999", 404}, {"GET", "/api/findings/%31", 404},
		{"GET", "/api/unknown", 404}, {"GET", "/raw/engagement.db", 404},
		{"GET", "/engagement.db", 404}, {"GET", "/secret-hits/", 404},
	} {
		w := serveReportRequest(h, tc.method, tc.path)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal(w.Header())
		}
	}
	for _, path := range []string{"/api/findings", "/api/runs", "/api/coverage"} {
		w := serveReportRequest(h, "GET", path)
		data := decodeServerJSON(t, w)
		if data["total"] != float64(0) {
			t.Fatal(path, data)
		}
	}
}
