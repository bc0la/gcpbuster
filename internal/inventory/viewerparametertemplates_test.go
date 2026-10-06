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

func TestParameterTemplateRawPayloadScopedNoRender(t *testing.T) {
	for _, region := range []string{"global", "us-central1"} {
		parent := "projects/123/locations/" + region
		template := parent + "/templates/password_blueprint"
		version := template + "/versions/v1"
		value := "password: EXAMPLE_FULL_VALUE\nregion: {{.region}}\n"
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "GET" || r.URL.Host != "parametermanager.googleapis.com" || strings.Contains(r.URL.Path, ":") || r.URL.Query().Has("view") {
				t.Fatal("unreviewed template operation", r.URL)
			}
			switch r.URL.Path {
			case "/v1/" + parent + "/templates":
				return response(200, `{"templates":[{"name":"`+template+`"}]}`), nil
			case "/v1/" + template + "/versions":
				return response(200, `{"templateVersions":[{"name":"`+version+`"}]}`), nil
			case "/v1/" + version:
				body, _ := json.Marshal(Object{"name": version, "payload": Object{"data": base64.StdEncoding.EncodeToString([]byte(value))}, "unreviewed": "DO_NOT_CAPTURE"})
				return response(200, string(body)), nil
			default:
				t.Fatal(r.URL)
				return nil, nil
			}
		})
		c.viewerPolicy.permissions = map[string]bool{"parametermanager.templates.list": true, "parametermanager.templateVersions.list": true, "parametermanager.templateVersions.get": true}
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		var out Snapshot
		c.collectParameterTemplates(context.Background(), &out, parent, region, "demo", "projects/123", &secretCollectionBudget{})
		ss := c.SecretCapture.Samples()
		if calls != 3 || len(ss) != 1 || string(ss[0].Data) != value || ss[0].SourceType != "parameter_template_raw" || hasCoverage(out, "failed") {
			t.Fatal(out, ss, calls)
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), "EXAMPLE_FULL_VALUE") || strings.Contains(string(b), "DO_NOT_CAPTURE") {
			t.Fatal("payload persisted")
		}
		fresh := NewSecretCapture(0, 0, 0)
		asset := NewAsset("//parametermanager.googleapis.com/"+version, "parametermanager.googleapis.com/TemplateVersion", Object{"name": version, "payload": Object{"data": base64.StdEncoding.EncodeToString([]byte(value))}})
		fresh.CaptureInventory([]Asset{asset})
		if len(fresh.Samples()) != 1 || string(fresh.Samples()[0].Data) != value {
			t.Fatal("offline raw template omitted")
		}
	}
}

func TestParameterTemplateGuardAndForeignPayload(t *testing.T) {
	u, _ := url.Parse("https://parametermanager.googleapis.com/v1/projects/123/locations/us-central1/templates/t/versions/v")
	q := url.Values{"fields": {parameterTemplateVersionFields}}
	p, err := parameterTemplatePermission("GET", u, q)
	if err != nil || len(p) != 1 || p[0] != "parametermanager.templateVersions.get" {
		t.Fatal(p, err)
	}
	for _, key := range []string{"view", "render", "fields"} {
		bad := url.Values{"fields": {parameterTemplateVersionFields}}
		bad.Set(key, "FULL")
		if _, err := parameterTemplatePermission("GET", u, bad); err == nil {
			t.Fatal("unreviewed query allowed", key)
		}
	}
	u.Path += ":render"
	if _, err := parameterTemplatePermission("GET", u, q); err == nil {
		t.Fatal("render allowed")
	}
	c := &Client{SecretCapture: NewSecretCapture(0, 0, 0)}
	expected := "projects/123/locations/global/templates/t/versions/v"
	for _, d := range []Object{{"name": "projects/999/locations/global/templates/t/versions/v", "payload": Object{"data": "YQ=="}}, {"name": expected, "payload": Object{"data": "%%%"}}, {"name": expected}, {"name": expected, "payload": Object{"data": base64.StdEncoding.EncodeToString(make([]byte, (4<<20)+1))}}} {
		if err := c.captureParameterTemplateVersion(d, expected, "global", "demo", "projects/123"); err == nil {
			t.Fatal("invalid payload accepted")
		}
	}
	if len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("foreign payload captured")
	}
}

func TestParameterTemplateSharedBudgetStopsBeforeRead(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("exhausted template budget made request")
		return nil, nil
	})
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	var out Snapshot
	c.collectParameterTemplates(context.Background(), &out, "projects/123/locations/global", "global", "demo", "projects/123", &secretCollectionBudget{pages: 1000})
	if !hasCoverage(out, "incomplete") || len(c.SecretCapture.Samples()) != 0 {
		t.Fatal(out)
	}
}
