package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParameterManagerRawPayloadNoRenderAndPartial(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || strings.Contains(r.URL.Path, ":") {
			t.Fatal("unexpected method")
		}
		switch r.URL.Path {
		case "/v1/projects/123/locations/global/templates", "/v1/projects/123/locations/us-central1/templates":
			return response(200, `{}`), nil
		case "/v1/projects/123/locations":
			return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1"}]}`), nil
		case "/v1/projects/123/locations/us-central1/parameters":
			if r.URL.Host != "parametermanager.us-central1.rep.googleapis.com" {
				t.Fatal("wrong residency host")
			}
			return response(403, `{"error":{"message":"SECRET_SENTINEL"}}`), nil
		case "/v1/projects/123/locations/global/parameters":
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"parameters":[{"name":"projects/evil/locations/global/parameters/leak"},{"name":"projects/demo/locations/global/parameters/config"}],"nextPageToken":"two"}`), nil
			}
			return response(200, `{}`), nil
		case "/v1/projects/123/locations/global/parameters/config/versions":
			return response(200, `{"parameterVersions":[{"name":"projects/123/locations/global/parameters/config/versions/v1"},{"name":"projects/123/locations/global/parameters/config/versions/off"}]}`), nil
		case "/v1/projects/123/locations/global/parameters/config/versions/v1":
			if r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != parameterFullFields {
				t.Fatal("wrong full view")
			}
			payload := base64.StdEncoding.EncodeToString([]byte(`password=SECRET_SENTINEL __REF__("//secretmanager.googleapis.com/projects/other/secrets/s/versions/1")`))
			return response(200, `{"name":"projects/demo/locations/global/parameters/config/versions/v1","payload":{"data":"`+payload+`"}}`), nil
		case "/v1/projects/123/locations/global/parameters/config/versions/off":
			return response(200, `{"name":"projects/123/locations/global/parameters/config/versions/off","disabled":true,"payload":{"data":"U0VDUkVU"}}`), nil
		}
		t.Fatal("unexpected endpoint")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"parametermanager.locations.list": true, "parametermanager.parameters.list": true, "parametermanager.parameterVersions.list": true, "parametermanager.parameterVersions.get": true}
	c.viewerPolicy.permissions["parametermanager.templates.list"] = true
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerParameterManager(context.Background(), &s, "demo", "projects/123")
	samples := c.SecretCapture.Samples()
	if calls != 9 || len(samples) != 1 || !strings.Contains(string(samples[0].Data), "SECRET_SENTINEL") {
		t.Fatalf("wrong capture count=%d calls=%d", len(samples), calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") || strings.Contains(string(b), "__REF__") {
		t.Fatal("raw payload persisted")
	}
}

func TestParameterManagerGuardAndMalformedUnknown(t *testing.T) {
	base := "https://parametermanager.googleapis.com/v1/projects/123/locations/global/parameters/p/versions/v"
	q := url.Values{"view": {"FULL"}, "fields": {parameterFullFields}}
	for _, target := range []string{base + ":render", strings.Replace(base, "parametermanager.googleapis.com", "evil.test", 1), strings.Replace(base, "/global/", "/us-central1/", 1), base + "/extra"} {
		u, _ := url.Parse(target)
		if _, err := parameterManagerPermission("GET", u, q); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	u, _ := url.Parse(base)
	if _, err := parameterManagerPermission("POST", u, q); err == nil {
		t.Fatal("write accepted")
	}
	if _, err := parameterManagerPermission("GET", u, q); err != nil {
		t.Fatal(err)
	}
	namedTemplates, _ := url.Parse(strings.Replace(base, "/parameters/p/", "/parameters/templates/", 1))
	if permissions, err := parameterManagerPermission("GET", namedTemplates, q); err != nil || len(permissions) != 1 || permissions[0] != "parametermanager.parameterVersions.get" {
		t.Fatal("parameter name confused with template collection", permissions, err)
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected transport without baseline")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	s := Snapshot{}
	c.CollectViewerParameterManager(context.Background(), &s, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("baseline bypass")
	}
	name := "projects/123/locations/global/parameters/p/versions/v"
	for _, raw := range []Object{{"name": name, "payload": Object{"data": "not base64"}}, {"name": name, "disabled": "false", "payload": Object{"data": "YQ=="}}, {"name": "projects/evil/locations/global/parameters/p/versions/v", "payload": Object{"data": "YQ=="}}} {
		if c.captureParameterVersion(raw, name, "global", "demo", "projects/123") == nil {
			t.Fatal("malformed payload accepted")
		}
	}
}
