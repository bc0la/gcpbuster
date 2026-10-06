package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAppHostingGuardSelectedReadOnly(t *testing.T) {
	for _, tc := range []struct{ path, fields, permission string }{{"/v1/projects/123/locations", appHostingLocationFields, "firebaseapphosting.locations.list"}, {"/v1/projects/123/locations/us-central1/backends", appHostingBackendFields, "firebaseapphosting.backends.list"}, {"/v1/projects/123/locations/us-central1/backends/b/builds", appHostingBuildFields, "firebaseapphosting.builds.list"}} {
		u, _ := url.Parse("https://firebaseapphosting.googleapis.com" + tc.path)
		q := url.Values{"fields": {tc.fields}, "pageSize": {"100"}}
		p, err := appHostingPermission("GET", u, q)
		if err != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, err)
		}
		q.Set("fields", "*")
		if _, err := appHostingPermission("GET", u, q); err == nil {
			t.Fatal("wildcard allowed")
		}
		q.Set("fields", tc.fields)
		if _, err := appHostingPermission("POST", u, q); err == nil {
			t.Fatal("write allowed")
		}
	}
}

func TestAppHostingCollectorAndOfflineCapture(t *testing.T) {
	body := `{"builds":[{"name":"projects/demo/locations/us-central1/backends/b/builds/build","config":{"effectiveEnv":[{"variable":"PASSWORD","value":"PLAINTEXT_EXAMPLE"},{"variable":"REFERENCED","secret":"projects/demo/secrets/key/versions/1"},{"variable":"BAD_UNION","value":"DO_NOT_CAPTURE","secret":"ref"}]},"source":{"archive":"DO_NOT_CAPTURE"},"buildLogsUri":"DO_NOT_CAPTURE"}]}`
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "firebaseapphosting.googleapis.com" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/123/locations":
			return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`), nil
		case "/v1/projects/123/locations/us-central1/backends":
			return response(200, `{"backends":[{"name":"projects/demo/locations/us-central1/backends/b"}]}`), nil
		case "/v1/projects/123/locations/us-central1/backends/b/builds":
			return response(200, body), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = map[string]bool{"firebaseapphosting.locations.list": true, "firebaseapphosting.backends.list": true, "firebaseapphosting.builds.list": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	var s Snapshot
	c.CollectViewerAppHosting(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || len(c.SecretCapture.Samples()) != 1 || hasCoverage(s, "failed") {
		t.Fatal(s, c.SecretCapture.Samples())
	}
	if string(c.SecretCapture.Samples()[0].Data) != "PASSWORD=PLAINTEXT_EXAMPLE" {
		t.Fatal(c.SecretCapture.Samples())
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PLAINTEXT_EXAMPLE") || strings.Contains(string(b), "DO_NOT_CAPTURE") {
		t.Fatal("raw config persisted")
	}
	var page Object
	json.Unmarshal([]byte(body), &page)
	a := NewAsset("//firebaseapphosting.googleapis.com/projects/123/locations/us-central1/backends/b/builds/build", "firebaseapphosting.googleapis.com/Build", Obj(List(page["builds"])[0]))
	fresh := NewSecretCapture(0, 0, 0)
	fresh.CaptureInventory([]Asset{a})
	if len(fresh.Samples()) != 1 {
		t.Fatal("offline missing approved env")
	}
	a.Name = "//firebaseapphosting.googleapis.com/projects/123/locations/us-central1/backends/b/builds/build/nested"
	fresh = NewSecretCapture(0, 0, 0)
	fresh.CaptureInventory([]Asset{a})
	if len(fresh.Samples()) != 0 {
		t.Fatal("malformed offline identity accepted")
	}
}
