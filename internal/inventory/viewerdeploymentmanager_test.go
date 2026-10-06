package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDeploymentManagerManifestCaptureBoundaries(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "www.googleapis.com" {
			t.Fatal("unexpected request")
		}
		switch r.URL.Path {
		case "/deploymentmanager/v2/projects/123/global/deployments":
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"deployments":[{"name":"dep","selfLink":"https://www.googleapis.com/deploymentmanager/v2/projects/demo/global/deployments/dep"},{"name":"foreign","selfLink":"https://www.googleapis.com/deploymentmanager/v2/projects/other/global/deployments/foreign"}],"nextPageToken":"two"}`), nil
			}
			return response(200, `{}`), nil
		case "/deploymentmanager/v2/projects/123/global/deployments/dep/manifests":
			return response(200, `{"manifests":[{"name":"manifest-1"}]}`), nil
		case "/deploymentmanager/v2/projects/123/global/deployments/dep/manifests/manifest-1":
			if r.URL.Query().Get("fields") != manifestContentFields {
				t.Fatal("wrong mask")
			}
			return response(200, `{"name":"manifest-1","config":{"content":"password: SECRET_SENTINEL"},"imports":[{"content":"import-secret"}],"expandedConfig":"expanded-secret","layout":"layout-secret","unreviewed":"DO_NOT_KEEP"}`), nil
		}
		t.Fatal("unexpected endpoint")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"deploymentmanager.deployments.list": true, "deploymentmanager.manifests.list": true, "deploymentmanager.manifests.get": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerDeploymentManager(context.Background(), &s, "demo", "projects/123")
	if calls != 4 || len(c.SecretCapture.Samples()) != 4 {
		t.Fatalf("calls=%d samples=%d", calls, len(c.SecretCapture.Samples()))
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") || strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal("manifest persisted")
	}
	incomplete := false
	for _, v := range s.Coverage {
		incomplete = incomplete || v.Status == "failed"
	}
	if !incomplete {
		t.Fatal("foreign identity not incomplete")
	}
}

func TestDeploymentManagerGuardAndMalformed(t *testing.T) {
	target := "https://www.googleapis.com/deploymentmanager/v2/projects/123/global/deployments/dep/manifests/m"
	u, _ := url.Parse(target)
	q := url.Values{"fields": {manifestContentFields}}
	if p, err := deploymentManagerPermission("GET", u, q); err != nil || len(p) != 1 || p[0] != "deploymentmanager.manifests.get" {
		t.Fatal("valid get denied")
	}
	for _, bad := range []string{target + ":delete", target + "/extra", strings.Replace(target, "www.googleapis.com", "evil.test", 1), strings.Replace(target, "/v2/", "/v2beta/", 1)} {
		u, _ := url.Parse(bad)
		if _, err := deploymentManagerPermission("GET", u, q); err == nil {
			t.Fatal("bad path accepted")
		}
	}
	if _, err := deploymentManagerPermission("POST", u, q); err == nil {
		t.Fatal("write accepted")
	}
	u, _ = url.Parse(target)
	if _, err := deploymentManagerPermission("GET", u, url.Values{"fields": {"*"}}); err == nil {
		t.Fatal("wildcard accepted")
	}
	c := &Client{SecretCapture: NewSecretCapture(0, 0, 0)}
	path := strings.TrimPrefix(target, "https://www.googleapis.com")
	for _, raw := range []Object{{"name": "wrong"}, {"name": "m", "config": "invalid"}, {"name": "m", "imports": []any{nil}}, {"name": "m", "layout": true}} {
		if c.captureDeploymentManifest(raw, path, "m", "demo", "projects/123") == nil {
			t.Fatal("malformed accepted")
		}
	}
	if len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("partial malformed capture")
	}
}
