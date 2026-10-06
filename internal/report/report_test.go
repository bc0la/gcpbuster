package report

import (
	"context"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportEscapesResourceContentAndRejectsWrites(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	err = e.Write(context.Background(), findings.Finding{ProjectID: "test", Module: "public_iam", Severity: findings.SevHigh, Title: `<script>alert('x')</script>`, ResourceName: `<img src=x onerror=alert(1)>`})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(e)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/", nil))
	if r.Code != 200 || strings.Contains(r.Body.String(), "<img src=x") || !strings.Contains(r.Body.String(), "&lt;img") {
		t.Fatal("unsafe HTML", r.Body.String())
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("POST", "/", nil))
	if r.Code != 405 {
		t.Fatal(r.Code)
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/raw/engagement.db", nil))
	if r.Code != 404 {
		t.Fatal("raw database exposed", r.Code)
	}
}
