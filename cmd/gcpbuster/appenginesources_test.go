package main

import (
	"bytes"
	"context"
	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppEngineSourceReportRedaction(t *testing.T) {
	t.Setenv("APP_SOURCE_TEST_TOKEN", "fixture-token")
	c := inventory.Client{TokenEnv: "APP_SOURCE_TEST_TOKEN", HTTP: &http.Client{Transport: contentTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"name":"source.env","generation":"42","size":"29"}`
		if r.URL.Host == "appengine.googleapis.com" {
			body = `{"id":"v1","name":"apps/my-project/services/default/versions/v1","envVariables":{"PASSWORD":"PRIVATE_ENV_VALUE"},"deployment":{"files":{"source.env":{"sourceUrl":"https://storage.googleapis.com/test-bucket/source.env"}}}}`
		} else if r.URL.Query().Get("alt") == "media" {
			body = "password=PRIVATE_SOURCE_VALUE"
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	s := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//appengine.googleapis.com/apps/my-project/services/default/versions/v1", "appengine.googleapis.com/Version", nil)}}
	c.RefreshAppEngineSources(context.Background(), &s)
	c.CollectSources(context.Background(), &s, inventory.StorageOptions{ScanContent: true, MaxObjects: 10, MaxObjectBytes: 4096, MaxArchiveBytes: 8192, MaxArchiveEntries: 10})
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "configuration_secrets" || ch.ID == "gcs_content_secrets" {
			selected = append(selected, ch)
		}
	}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = assess(context.Background(), cmd, e, s, selected, false)
	e.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"findings.json", "report.html", "engagement.db"} {
		b, err := os.ReadFile(filepath.Join(e.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("PRIVATE_ENV_VALUE")) || bytes.Contains(b, []byte("PRIVATE_SOURCE_VALUE")) || bytes.Contains(b, []byte("fixture-token")) {
			t.Fatal("secret persisted", name)
		}
		if name == "findings.json" && (!bytes.Contains(b, []byte("configuration_secrets")) || !bytes.Contains(b, []byte("gcs_content_secrets"))) {
			t.Fatal("missing findings", string(b))
		}
	}
}
