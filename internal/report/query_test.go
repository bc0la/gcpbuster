package report

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestQueryPagesFiltersAndSecretDetails(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	for i := 0; i < 63; i++ {
		title := "ordinary"
		if i == 0 {
			title = "literal_%"
		}
		f := findings.Finding{ProjectID: "demo", Module: "secrets_scan", Severity: findings.SevHigh, Title: title, Detail: map[string]string{"secret": "SECRET_DETAIL_SENTINEL"}, RawOutputPath: "../outside"}
		if err := e.Write(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Write(ctx, findings.Finding{ProjectID: "other", Module: "public_iam", Severity: findings.SevLow, Title: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	h := APIHandler(e.DB())
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		return r
	}
	r := request("/api/findings?page=2&page_size=50&category=secrets")
	if r.Code != 200 || strings.Contains(r.Body.String(), "SECRET_DETAIL_SENTINEL") || strings.Contains(r.Body.String(), "detail") || strings.Contains(r.Body.String(), "../outside") {
		t.Fatalf("unsafe list: %d %s", r.Code, r.Body.String())
	}
	var page struct {
		Findings    []BriefRow
		Total, Page int
		PageSize    int `json:"page_size"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 63 || page.Page != 2 || page.PageSize != 50 || len(page.Findings) != 13 || page.Findings[0].ID != 51 {
		t.Fatalf("invalid bounded page: %+v", page)
	}
	r = request("/api/findings?q=" + url.QueryEscape("_%"))
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("LIKE wildcard not escaped: %d %s", r.Code, r.Body.String())
	}
	r = request("/api/findings?q=SECRET_DETAIL_SENTINEL")
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatal("secret details searchable by default")
	}
	r = request("/api/findings/1")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "SECRET_DETAIL_SENTINEL") || strings.Contains(r.Body.String(), "../outside") {
		t.Fatalf("detail wrong: %d %s", r.Code, r.Body.String())
	}
	r = request("/api/summary")
	var summary summaryResult
	if err := json.Unmarshal(r.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Total != 64 || len(summary.Categories) != 4 || summary.Severity["high"] != 63 || len(summary.Projects) != 2 {
		t.Fatalf("invalid aggregates: %s", r.Body.String())
	}
	for _, path := range []string{"/api/findings?page=0", "/api/findings?page_size=201", "/api/findings?page=1&page=2", "/api/findings?category=bad", "/api/findings?severity=bad", "/api/findings/0", "/api/findings/1/extra"} {
		if r := request(path); r.Code != 400 {
			t.Fatalf("invalid input not rejected: %s %d", path, r.Code)
		}
	}
	if r := request("/api/findings/999999"); r.Code != 404 {
		t.Fatal("missing finding not 404")
	}
	r = request("/api/findings?module=" + url.QueryEscape("' OR 1=1 --"))
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatal("SQL filter injection")
	}
}

func TestQueryRunsAndCoveragePagination(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	if err := e.MarkModule(ctx, "demo", "module", "failed", "safe failure"); err != nil {
		t.Fatal(err)
	}
	if err := e.SetMeta(ctx, "coverage", `[{"source":"one","status":"completed","count":1},{"source":"two","status":"failed","error":"safe"}]`); err != nil {
		t.Fatal(err)
	}
	h := APIHandler(e.DB())
	for path, want := range map[string]string{"/api/runs?page_size=1": "safe failure", "/api/coverage?page=2&page_size=1": "two"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 || !strings.Contains(r.Body.String(), want) {
			t.Fatalf("%s %d %s", path, r.Code, r.Body.String())
		}
	}
}
