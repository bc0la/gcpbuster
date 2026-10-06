package report

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestFilteredExportAllPagesAndAssets(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	created := time.Date(2026, 10, 6, 1, 2, 3, 0, time.UTC)
	ctx := context.Background()
	for i := 0; i < 301; i++ {
		f := findings.Finding{ProjectID: "demo", Region: "us-central1", Module: "secrets_scan", Severity: findings.SevHigh, Title: "credential candidate", ResourceName: "//gcpbuster.googleapis.com/secretFindings/opaque", Detail: map[string]any{"evidence": map[string]string{"source": "//run.googleapis.com/projects/demo/locations/us-central1/services/api", "match": "FULL_VALUE_SENTINEL"}, "remediation": "review safely"}, CreatedAt: created}
		if err := e.Write(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Write(ctx, findings.Finding{ProjectID: "other", Module: "public_iam", Severity: findings.SevLow, ResourceName: "//storage.googleapis.com/other"}); err != nil {
		t.Fatal(err)
	}
	h := ExportHandler(e.DB())
	req := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := req("/api/export/json?category=secrets&project=demo")
	var rows []exportRow
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 301 {
		t.Fatalf("export truncated: %d %d", w.Code, len(rows))
	}
	var detail map[string]any
	if json.Unmarshal(rows[0].Detail, &detail) != nil || rows[0].Region != "us-central1" || rows[0].CreatedAt == nil || detail["remediation"] != "review safely" || !strings.Contains(string(rows[0].Detail), "FULL_VALUE_SENTINEL") {
		t.Fatal("complete detail/region/timestamp lost")
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatal("unsafe export headers")
	}
	w = req("/api/export/assets?category=secrets")
	if w.Code != 200 || w.Body.String() != "//run.googleapis.com/projects/demo/locations/us-central1/services/api\n" {
		t.Fatalf("asset source/dedup wrong: %d %s", w.Code, w.Body.String())
	}
	w = req("/api/export/json?project=missing")
	if w.Body.String() != "[]\n" {
		t.Fatal("empty export not empty array")
	}
	for _, path := range []string{"/api/export/json?page=2", "/api/export/assets?page_size=50", "/api/export/json?category=unknown", "/api/export/json?q=%zz", "/api/export/assets?module=x&module=y"} {
		if w := req(path); w.Code != 400 {
			t.Fatalf("bad query accepted %s %d", path, w.Code)
		}
	}
}

func TestAssetExportPermissionSuffixAndNoSecretFallback(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	base := "//storage.googleapis.com/my-bucket"
	for _, resource := range []string{base, base + "/permission-analysis/abcdefabcdefabcdefabcdef", "", "invalid\nidentifier", "SYNTHETIC_ACTUAL_TOKEN", "javascript:alert(1)", "https://user:credential@example.invalid/path", "https://example.invalid/path?token=secret", "https://example.invalid/path#secret"} {
		if err := e.Write(context.Background(), findings.Finding{Module: "public_iam", ResourceName: resource, Title: "SECRET_TITLE_SENTINEL", Detail: map[string]string{"value": "FULL_VALUE_SENTINEL"}}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	ExportHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/export/assets", nil))
	if w.Code != 200 || w.Body.String() != base+"\n" {
		t.Fatalf("unsafe or duplicated assets: %d %s", w.Code, w.Body.String())
	}
}

func TestAssetExportPreservesRealUnicodeAndSpacedIdentifiers(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	resources := []string{"//storage.googleapis.com/bucket/目录/report 2026.csv", "gs://bucket/目录/name%20encoded", "https://example.invalid/a%20resource", "workspace/groups/工程 team"}
	for _, resource := range resources {
		if err := e.Write(context.Background(), findings.Finding{Module: "public_iam", ResourceName: resource, Detail: map[string]string{"value": "NOT_AN_ASSET_SECRET"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Write(context.Background(), findings.Finding{Module: "secrets_scan", ResourceName: "//gcpbuster.googleapis.com/secretFindings/opaque", Detail: map[string]any{"evidence": map[string]string{"source": "//storage.googleapis.com/bucket/目录/config 2026.txt", "match": "NOT_AN_ASSET_SECRET"}}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ExportHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/export/assets", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, resource := range append(resources, "//storage.googleapis.com/bucket/目录/config 2026.txt") {
		if !strings.Contains(w.Body.String(), resource+"\n") {
			t.Fatalf("genuine identifier omitted: %q", resource)
		}
	}
	if strings.Contains(w.Body.String(), "NOT_AN_ASSET_SECRET") || strings.Contains(w.Body.String(), "secretFindings") {
		t.Fatal("evidence value or wrapper exported")
	}
}

func TestExportFailureDoesNotPublishPartialDownload(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Write(context.Background(), findings.Finding{Module: "secrets_scan", Detail: map[string]string{"match": "SECRET_SENTINEL"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB().Exec(`INSERT INTO findings(project_id,module,severity,resource_name,title,detail_json,created_at) VALUES('demo','secrets_scan','high','','bad','{invalid',CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ExportHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/export/json", nil))
	if w.Code != 500 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "SECRET_SENTINEL") {
		t.Fatalf("partial success/secret exposed: %d %s", w.Code, w.Body.String())
	}
	files, err := os.ReadDir(tmp)
	if err != nil || len(files) != 0 {
		t.Fatal("private export spool retained")
	}
}
