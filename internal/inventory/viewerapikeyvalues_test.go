package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerAPIKeyValueTransientAndGuarded(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/v2/projects/123/locations/global/keys" {
			return response(200, `{"keys":[{"name":"projects/123/locations/global/keys/one"}]}`), nil
		}
		if r.URL.Path != "/v2/projects/123/locations/global/keys/one/keyString" || r.Method != "GET" || r.URL.Query().Get("fields") != "keyString" {
			t.Fatal("unexpected key request")
		}
		return response(200, `{"keyString":"SYNTHETIC_KEY_VALUE_ONLY"}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"apikeys.keys.list": true, "apikeys.keys.getKeyString": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(c.SecretCapture.Samples()) != 1 {
		t.Fatal(calls, c.SecretCapture.Samples())
	}
	encoded, _ := json.Marshal(s)
	if strings.Contains(string(encoded), "SYNTHETIC_KEY_VALUE_ONLY") {
		t.Fatal("key leaked into inventory")
	}
	target := "https://apikeys.googleapis.com/v2/projects/123/locations/global/keys/one/keyString"
	for _, q := range []url.Values{{"fields": {"*"}}, {"fields": {"keyString"}, "alt": {"media"}}} {
		if _, err := viewerRequestPermissions("GET", target, q); err == nil {
			t.Fatal("unreviewed query accepted")
		}
	}
	if _, err := viewerRequestPermissions("POST", target, url.Values{"fields": {"keyString"}}); err == nil {
		t.Fatal("write accepted")
	}
	c.viewerPolicy.permissions = map[string]bool{"apikeys.keys.list": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	calls = 0
	s = Snapshot{}
	c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
	if calls != 1 || len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("missing baseline permission did not fail closed")
	}
}
