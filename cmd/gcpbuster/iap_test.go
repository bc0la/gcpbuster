package main

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestIAPPolicyReportPipeline(t *testing.T) {
	t.Setenv("IAP_TEST_TOKEN", "fixture-token")
	c := inventory.Client{TokenEnv: "IAP_TEST_TOKEN", HTTP: &http.Client{Transport: contentTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" {
			body := `{"name":"projects/123","projectId":"my-project"}`
			if r.URL.Host == "compute.googleapis.com" {
				body = `{"items":[{"name":"backend","protocol":"HTTPS","iap":{"enabled":false,"oauth2ClientSecret":"PRIVATE_BACKEND_VALUE"}}]}`
			}
			if r.URL.Host == "appengine.googleapis.com" {
				body = `{"services":[{"id":"default","name":"apps/my-project/services/default","networkSettings":{"ingressTrafficAllowed":"INGRESS_TRAFFIC_ALLOWED_ALL"}}]}`
				if r.URL.Path == "/v1/apps/my-project" {
					body = `{"name":"apps/my-project","id":"my-project","iap":{"enabled":false}}`
				}
				if strings.HasSuffix(r.URL.Path, "/versions") {
					body = `{"versions":[{"id":"v1","name":"apps/my-project/services/default/versions/v1"}]}`
				}
			}
			if r.URL.Host == "iap.googleapis.com" {
				name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/"), ":iapSettings")
				data, _ := json.Marshal(inventory.Object{"name": name, "accessSettings": inventory.Object{"corsSettings": inventory.Object{"allowHttpOptions": true}, "oauthSettings": inventory.Object{"clientSecret": "PRIVATE_SETTINGS_SECRET"}}})
				body = string(data)
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		if r.URL.Host != "iap.googleapis.com" || r.Method != "POST" {
			t.Fatal(r.URL)
		}
		body := `{"version":3,"bindings":[{"role":"roles/iap.httpsResourceAccessor","members":["allUsers"],"condition":{"title":"review-condition","expression":"true"}}]}`
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	s := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", nil)}}
	priorVersion := inventory.NewAsset("//appengine.googleapis.com/apps/my-project/services/default/versions/v1", "appengine.googleapis.com/Version", inventory.Object{"runtime": "go125"})
	priorVersion.Ancestors = []string{"projects/123", "folders/9", "organizations/1"}
	s.Assets = append(s.Assets, priorVersion)
	c.CollectIAPBackends(context.Background(), &s, []string{"projects/123"})
	s.Assets = mergeAssets(s.Assets)
	c.CollectAppEngineIAP(context.Background(), &s)
	s.Assets = mergeAssets(s.Assets)
	for _, a := range s.Assets {
		if a.Name == priorVersion.Name && (inventory.Str(a.Resource.Data["runtime"]) != "go125" || len(a.Ancestors) != 3) {
			t.Fatal("discovery replaced richer inventory", a)
		}
	}
	c.CollectIAPSettings(context.Background(), &s)
	c.CollectIAPPolicies(context.Background(), &s)
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "iap_access_grants" || ch.ID == "iap_backend_protection" || ch.ID == "iap_settings" || ch.ID == "appengine_protection" || ch.ID == "appengine_ingress" {
			selected = append(selected, ch)
		}
	}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"appengine_protection", "appengine_ingress", "appengine-my-project/services/default/versions/v1", "iap_settings", "iap_backend_protection", "iap_access_grants", "//iap.googleapis.com/projects/123/iap_web/compute/services/backend", "review-condition", "medium"} {
		if !bytes.Contains(b, []byte(expected)) {
			t.Fatal("missing evidence", expected, string(b))
		}
	}
	if bytes.Contains(b, []byte("fixture-token")) || bytes.Contains(b, []byte("PRIVATE_BACKEND_VALUE")) || bytes.Contains(b, []byte("PRIVATE_SETTINGS_SECRET")) {
		t.Fatal("token leaked")
	}
}
