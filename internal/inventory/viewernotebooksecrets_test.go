package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestNotebookSecretsScopedMetadata(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/v2/projects/123/locations/-/instances":
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"instances":[{"name":"projects/demo/locations/us-central1-a/instances/n"},{"name":"projects/other/locations/us-central1-a/instances/foreign"}],"nextPageToken":"two"}`), nil
			}
			return response(200, `{}`), nil
		case "/v2/projects/123/locations/us-central1-a/instances/n":
			return response(200, `{"name":"projects/demo/locations/us-central1-a/instances/n","gceSetup":{"metadata":{"startup-script":"echo SECRET_SENTINEL","password":"TEST_PASSWORD","post-startup-script":"gs://other/scripts/setup.sh"},"serviceAccounts":[{"credentials":"DO_NOT_KEEP"}]},"proxyUri":"DO_NOT_KEEP"}`), nil
		}
		t.Fatal("unexpected endpoint")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"notebooks.instances.list": true, "notebooks.instances.get": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerNotebookSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 3 || len(c.SecretCapture.Samples()) != 3 {
		t.Fatalf("calls=%d samples=%d", calls, len(c.SecretCapture.Samples()))
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") || strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal("secret persisted")
	}
	for _, sample := range c.SecretCapture.Samples() {
		if strings.Contains(string(sample.Data), "DO_NOT_KEEP") {
			t.Fatal("unreviewed field captured")
		}
	}
}

func TestNotebookSecretsGuardMalformedAndBaseline(t *testing.T) {
	target := "https://notebooks.googleapis.com/v2/projects/123/locations/us-central1-a/instances/n"
	u, _ := url.Parse(target)
	q := url.Values{"fields": {notebookGetFields}}
	if _, e := notebookSecretsPermission("GET", u, q); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{target + ":getHealth", target + ":generateAccessToken", target + "/content", strings.Replace(target, "/v2/", "/v1/", 1), strings.Replace(target, "notebooks.googleapis.com", "evil.test", 1)} {
		u, _ := url.Parse(bad)
		if _, e := notebookSecretsPermission("GET", u, q); e == nil {
			t.Fatal("unreviewed endpoint")
		}
	}
	u, _ = url.Parse(target)
	if _, e := notebookSecretsPermission("POST", u, q); e == nil {
		t.Fatal("write accepted")
	}
	if _, e := notebookSecretsPermission("GET", u, url.Values{"fields": {"*"}}); e == nil {
		t.Fatal("wildcard accepted")
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("baseline bypass"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerNotebookSecrets(context.Background(), &s, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("capture without baseline")
	}
	name := "projects/123/locations/us-central1-a/instances/n"
	for _, raw := range []Object{{"name": "wrong"}, {"name": name, "gceSetup": "bad"}, {"name": name, "gceSetup": map[string]any{"metadata": map[string]any{"password": true}}}} {
		if c.captureNotebookMetadata(raw, name, "demo", "projects/123") == nil {
			t.Fatal("malformed accepted")
		}
	}
}
