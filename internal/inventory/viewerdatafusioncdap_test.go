package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func cdapTestPermissions() map[string]bool {
	return map[string]bool{"datafusion.instances.get": true, "datafusion.namespaces.list": true, "datafusion.namespaces.get": true, "datafusion.pipelines.list": true, "datafusion.pipelines.get": true, "datafusion.pipelineConnections.list": true}
}

func TestCDAPMetadataReaderNoRuntimePermission(t *testing.T) {
	const instance = "projects/123/locations/us-central1/instances/etl"
	const host = "etl-demo-dot-usc1.datafusion.googleusercontent.com"
	paths := map[string]bool{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || (r.URL.Host != "datafusion.googleapis.com" && r.URL.RawQuery != "") {
			t.Fatal("nonmetadata request", r.URL)
		}
		paths[r.URL.Path] = true
		if r.URL.Host == "datafusion.googleapis.com" {
			if r.URL.Path != "/v1/"+instance || r.URL.Query().Get("fields") != dataFusionEndpointFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"projects/demo/locations/us-central1/instances/etl","apiEndpoint":"https://`+host+`/api"}`), nil
		}
		if r.URL.Host != host {
			t.Fatal("escaped endpoint", r.URL)
		}
		switch r.URL.Path {
		case "/api/v3/namespaces":
			return response(200, `[{"name":"chosen","config":{"credential":"DO_NOT_CAPTURE"}}]`), nil
		case "/api/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/chosen/connections":
			return response(200, `[{"connectionId":"mysql","plugin":{"properties":{"password":"CONNECTION_EXAMPLE"}},"privateKey":"DO_NOT_CAPTURE"}]`), nil
		case "/api/v3/namespaces/chosen/apps":
			return response(200, `[{"name":"etl","artifact":{"name":"cdap-data-pipeline"}},{"name":"unrelated","artifact":{"name":"other"}}]`), nil
		case "/api/v3/namespaces/chosen/apps/etl":
			body, _ := json.Marshal(Object{"name": "etl", "configuration": `{"properties":{"password":"PIPELINE_EXAMPLE"},"stages":[{"plugin":{"properties":{"password":"STAGE_EXAMPLE"}},"privateKey":"DO_NOT_CAPTURE"}],"postActions":[{"plugin":{"properties":{"token":"POST_EXAMPLE"}}}],"outputs":"DO_NOT_CAPTURE"}`})
			return response(200, string(body)), nil
		default:
			t.Fatal("guessed or unreviewed endpoint", r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = cdapTestPermissions()
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	var out Snapshot
	c.viewerDataFusionCDAP(context.Background(), &out, "demo", "projects/123", instance, "us-central1", &secretCollectionBudget{})
	ss := c.SecretCapture.Samples()
	if len(ss) != 4 || hasCoverage(out, "failed") {
		t.Fatal(out, ss)
	}
	all := ""
	for _, s := range ss {
		all += string(s.Data) + "\n"
		if !strings.Contains(s.Resource, "/namespaces/chosen/") {
			t.Fatal("unbound namespace", s)
		}
	}
	for _, want := range []string{"CONNECTION_EXAMPLE", "PIPELINE_EXAMPLE", "STAGE_EXAMPLE", "POST_EXAMPLE"} {
		if !strings.Contains(all, want) {
			t.Fatal("missing selected property", want)
		}
	}
	if strings.Contains(all, "DO_NOT_CAPTURE") {
		t.Fatal("unselected data captured")
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "EXAMPLE") {
		t.Fatal("secret persisted in snapshot")
	}
	if paths["/api/v3/namespaces/default/apps"] {
		t.Fatal("default namespace guessed")
	}
}

func TestCDAPBindingAndRoutesFailClosed(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unreviewed network read"); return nil, nil })
	c.viewerPolicy.permissions = cdapTestPermissions()
	instance := "projects/123/locations/us-central1/instances/etl"
	for _, endpoint := range []string{"http://etl.datafusion.googleusercontent.com/api", "https://evil.example/api", "https://etl.datafusion.googleusercontent.com:443/api", "https://user@etl.datafusion.googleusercontent.com/api", "https://etl.datafusion.googleusercontent.com/api?secret=x", "https://etl.datafusion.googleusercontent.com/api/v3", "https://etl.datafusion.googleusercontent.com/%61pi"} {
		if _, err := c.bindCDAP(Object{"name": instance, "apiEndpoint": endpoint}, instance, "demo", "projects/123", "us-central1"); err == nil {
			t.Fatal("bad endpoint bound", endpoint)
		}
	}
	if _, err := c.bindCDAP(Object{"name": "projects/999/locations/us-central1/instances/etl", "apiEndpoint": "https://etl.datafusion.googleusercontent.com/api"}, instance, "demo", "projects/123", "us-central1"); err == nil {
		t.Fatal("foreign instance bound")
	}
	b, err := c.bindCDAP(Object{"name": instance, "apiEndpoint": "https://etl.datafusion.googleusercontent.com/api"}, instance, "demo", "projects/123", "us-central1")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v3/namespaces/chosen/securekeys/key", "/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/chosen/connections/test", "/v3/namespaces/chosen/apps/etl/runs", "/v3/namespaces/chosen/apps?x=y", "//evil.example/path", "/v3/namespaces/chosen/apps/../secret"} {
		if _, err := c.cdapRead(context.Background(), b, path, &secretCollectionBudget{}); err == nil {
			t.Fatal("unreviewed path allowed", path)
		}
	}
	delete(c.viewerPolicy.permissions, "datafusion.namespaces.list")
	if _, err := c.cdapRead(context.Background(), b, "/v3/namespaces", &secretCollectionBudget{}); err == nil {
		t.Fatal("missing role permission allowed")
	}
	other := &Client{}
	if _, err := other.cdapRead(context.Background(), b, "/v3/namespaces", &secretCollectionBudget{}); err == nil {
		t.Fatal("binding transferred clients")
	}
}

func TestCDAPTransportRejectsRedirectAndOversizedBody(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Host != "etl.datafusion.googleusercontent.com" {
				t.Fatal("redirect leaked auth", r.URL)
			}
			if oversized {
				return response(200, strings.Repeat("x", (4<<20)+1)), nil
			}
			res := response(302, "UPSTREAM_SECRET")
			res.Header.Set("Location", "https://evil.example/secret")
			return res, nil
		})
		c.viewerPolicy.permissions = cdapTestPermissions()
		b, err := c.bindCDAP(Object{"name": "projects/123/locations/us-central1/instances/etl", "apiEndpoint": "https://etl.datafusion.googleusercontent.com/api"}, "projects/123/locations/us-central1/instances/etl", "demo", "projects/123", "us-central1")
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.cdapRead(context.Background(), b, "/v3/namespaces", &secretCollectionBudget{})
		if err == nil || strings.Contains(err.Error(), "UPSTREAM_SECRET") || calls != 1 {
			t.Fatal(err, calls)
		}
	}
}

func TestOfflineCDAPApprovedConfigurationOnly(t *testing.T) {
	resource := "//datafusion.googleapis.com/projects/123/locations/us-central1/instances/etl/namespaces/chosen/"
	a := NewAsset(resource+"connections/mysql", DataFusionConnectionType, Object{"plugin": Object{"properties": Object{"password": "OFFLINE_CONNECTION"}}, "secureKey": "DO_NOT_CAPTURE"})
	b := NewAsset(resource+"pipelines/etl", DataFusionPipelineType, Object{"configuration": `{"stages":[{"plugin":{"properties":{"password":"OFFLINE_STAGE"}}}],"outputs":"DO_NOT_CAPTURE"}`})
	c := NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a, b})
	ss := c.Samples()
	if len(ss) != 2 {
		t.Fatal(ss)
	}
	for _, s := range ss {
		if strings.Contains(string(s.Data), "DO_NOT_CAPTURE") {
			t.Fatal(s)
		}
	}
	a.Name = resource + "connections/mysql/nested"
	c = NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	if len(c.Samples()) != 0 {
		t.Fatal("invalid offline identity accepted")
	}
}

func TestCDAPDuplicateMetadataIsIncomplete(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if pipeline {
				if strings.HasSuffix(r.URL.Path, "/apps") {
					return response(200, `[{"name":"etl","artifact":{"name":"cdap-data-pipeline"}},{"name":"etl","artifact":{"name":"cdap-data-pipeline"}}]`), nil
				}
				return response(200, `{"name":"etl","configuration":"{}"}`), nil
			}
			return response(200, `[{"connectionId":"db","plugin":{"properties":{"password":"FIRST_VALUE"}}},{"connectionId":"db","plugin":{"properties":{"password":"CONFLICT_VALUE"}}}]`), nil
		})
		c.viewerPolicy.permissions = cdapTestPermissions()
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		b, err := c.bindCDAP(Object{"name": "projects/123/locations/us-central1/instances/etl", "apiEndpoint": "https://etl.datafusion.googleusercontent.com/api"}, "projects/123/locations/us-central1/instances/etl", "demo", "projects/123", "us-central1")
		if err != nil {
			t.Fatal(err)
		}
		var out Snapshot
		if pipeline {
			c.viewerCDAPPipelines(context.Background(), &out, b, "ns", "us-central1", &secretCollectionBudget{})
		} else {
			c.viewerCDAPConnections(context.Background(), &out, b, "ns", "us-central1", &secretCollectionBudget{})
		}
		if !hasCoverage(out, "failed") {
			t.Fatal("duplicates appeared complete", out)
		}
		if pipeline && calls != 2 {
			t.Fatal("duplicate detail reread", calls)
		}
	}
}

func TestGeneralClientCannotReadUnboundCDAPDomain(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("generic client sent bearer to unbound CDAP")
		return nil, nil
	})
	if _, err := c.get(context.Background(), "https://etl.datafusion.googleusercontent.com/api/v3/namespaces", nil); err == nil {
		t.Fatal("generic CDAP URL allowed")
	}
}
