package report

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestSecretHitDownloadRequiresExactDatabaseReference(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	payload := "synthetic <script>alert('x')</script>"
	path, err := e.WriteSecretArtifact([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(e)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if get("/"+path).Code != 404 {
		t.Fatal("unreferenced file")
	}
	if err := e.Write(context.Background(), findings.Finding{Module: "configuration_secrets", Title: payload, RawOutputPath: path}); err != nil {
		t.Fatal(err)
	}
	w := get("/" + path)
	if w.Code != 200 || w.Body.String() != payload || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatal(w.Code, w.Header())
	}
	w = get("/api/findings/1")
	if strings.Contains(w.Body.String(), "<script>alert") || !strings.Contains(w.Body.String(), path) {
		t.Fatal(w.Body.String())
	}
	for _, bad := range []string{"/secret-hits/", "/secret-hits/../engagement.db", "/" + path + "?download=1", "/raw/engagement.db"} {
		if get(bad).Code != 404 {
			t.Fatal(bad)
		}
	}
	if err := e.Write(context.Background(), findings.Finding{Module: "configuration_secrets", RawOutputPath: "javascript:alert(1)"}); err != nil {
		t.Fatal(err)
	}
	_, rows, err := Read(e.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.RawOutputPath, "javascript") {
			t.Fatal(r)
		}
	}
}

func TestReportExportPrivateReplacementAndSymlinkRejection(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, name := range []string{"report.html", "findings.json"} {
		if err := os.WriteFile(filepath.Join(e.Dir, name), []byte("old"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Export(e); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.html", "findings.json"} {
		st, err := os.Stat(filepath.Join(e.Dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal(st, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.Dir, "report.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.Dir, "report.html")); err != nil {
		t.Fatal(err)
	}
	if err := Export(e); err == nil {
		t.Fatal("symlink accepted")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "unchanged" {
		t.Fatal("target modified")
	}
}
