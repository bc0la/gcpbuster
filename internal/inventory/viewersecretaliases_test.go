package inventory

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestSecretAliasDetailScopeAndProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Query().Get("fields") != secretAliasFields {
			t.Fatal("mask")
		}
		switch r.URL.Path {
		case "/v1/projects/123/secrets/s":
			return response(200, `{"name":"projects/demo/secrets/s","versionAliases":{"prod":"2"},"payload":{"data":"DO_NOT_KEEP"}}`), nil
		case "/v1/projects/123/locations/us-central1/secrets/r":
			if r.URL.Host != "secretmanager.us-central1.rep.googleapis.com" {
				t.Fatal("host")
			}
			return response(200, `{"name":"projects/123/locations/us-central1/secrets/r"}`), nil
		}
		t.Fatal("unexpected path")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"secretmanager.secrets.get": true}
	s := Snapshot{Assets: []Asset{NewAsset("//secretmanager.googleapis.com/projects/123/secrets/s", "secretmanager.googleapis.com/Secret", Object{}), NewAsset("//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/r", "secretmanager.googleapis.com/Secret", Object{}), NewAsset("//secretmanager.googleapis.com/projects/other/secrets/no", "secretmanager.googleapis.com/Secret", Object{})}}
	c.CollectViewerSecretAliases(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || Get(s.Assets[0].Resource.Data, "versionAliases", "prod") != "2" || s.Assets[1].Resource.Data["gcpbusterAliasesObserved"] != true {
		t.Fatalf("wrong results %d", calls)
	}
	if s.Assets[0].Resource.Data["payload"] != nil {
		t.Fatal("payload retained")
	}
}
func TestSecretAliasGuardProjection(t *testing.T) {
	u, _ := url.Parse("https://secretmanager.googleapis.com/v1/projects/123/secrets/s")
	q := url.Values{"fields": {secretAliasFields}}
	if _, e := secretAliasesPermission("GET", u, q); e != nil {
		t.Fatal(e)
	}
	if _, e := secretAliasesPermission("POST", u, q); e == nil {
		t.Fatal("write")
	}
	u.Path += ":access"
	if _, e := secretAliasesPermission("GET", u, q); e == nil {
		t.Fatal("payload")
	}
	for _, mapping := range []any{false, map[string]any{"latest": "1"}, map[string]any{"p": "0"}, map[string]any{"p": float64(1)}, map[string]any{"p": "01"}} {
		if _, e := viewerRegionalSecretProjection(Object{"versionAliases": mapping}, false); e == nil {
			t.Fatal("malformed alias")
		}
	}
	clean, e := viewerRegionalSecretProjection(Object{"versionAliases": map[string]any{"prod": "9223372036854775807"}}, false)
	if e != nil || Get(clean, "versionAliases", "prod") == nil {
		t.Fatal(e)
	}
}
