package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerModelArmorDiscoveredRegionsAndProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/floorSetting"):
			if r.URL.Host != "modelarmor.googleapis.com" {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"projects/demo/locations/global/floorSetting","enableFloorSettingEnforcement":false}`), nil
		case strings.HasSuffix(r.URL.Path, "/locations"):
			return response(200, `{"locations":[{"name":"projects/123/locations/europe-west1","locationId":"europe-west1"},{"name":"projects/foreign/locations/us-east1","locationId":"us-east1"}]}`), nil
		default:
			calls++
			if r.URL.Host != "modelarmor.europe-west1.rep.googleapis.com" {
				t.Fatal(r.URL)
			}
			if calls == 1 {
				return response(200, `{"templates":[{"name":"projects/123/locations/europe-west1/templates/one","filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"DISABLED"},"filterRuleSettings":{"custom":"SENSITIVE_SENTINEL"}},"templateMetadata":{"enforcementType":"INSPECT_ONLY","customPromptSafetyErrorMessage":"SENSITIVE_SENTINEL"}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"templates":[{"name":"projects/123/locations/europe-west1/templates/two","templateMetadata":{"enforcementType":"INSPECT_ONLY|INSPECT_AND_BLOCK"}}]}`), nil
		}
	})
	var out Snapshot
	c.CollectViewerModelArmor(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 3 || !hasCoverage(out, "failed") {
		t.Fatal(out, calls)
	}
	if out.Assets[2].Resource.Data["projection_complete"] != false {
		t.Fatal(out.Assets[2])
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SENSITIVE_SENTINEL") {
		t.Fatal("content retained")
	}
}
func TestViewerModelArmorGuardAndBaseline(t *testing.T) {
	ep := "https://modelarmor.europe-west1.rep.googleapis.com/v1/projects/123/locations/europe-west1/templates"
	q := url.Values{"fields": {viewerModelArmorTemplateFields}, "pageSize": {"100"}}
	p, e := viewerRequestPermissions("GET", ep, q)
	if e != nil || len(p) != 1 || p[0] != "modelarmor.templates.list" {
		t.Fatal(p, e)
	}
	for _, bad := range []string{strings.Replace(ep, "locations/europe-west1", "locations/us-east1", 1), ep + "/one:sanitizeUserPrompt", strings.Replace(ep, "modelarmor.europe-west1.rep", "modelarmor", 1)} {
		if _, e := viewerRequestPermissions("GET", bad, q); e == nil {
			t.Fatal(bad)
		}
	}
	if _, e := viewerRequestPermissions("POST", ep, q); e == nil {
		t.Fatal("write allowed")
	}
	q.Set("fields", "*")
	if _, e := viewerRequestPermissions("GET", ep, q); e == nil {
		t.Fatal("broad fields")
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	var out Snapshot
	c.CollectViewerModelArmor(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
func TestViewerModelArmorLateFailurePreservesTemplates(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "floorSetting") {
			return response(403, `denied`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/locations") {
			return response(200, `{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}]}`), nil
		}
		if r.URL.Query().Get("pageToken") != "" {
			return response(403, `denied`), nil
		}
		return response(200, `{"templates":[{"name":"projects/123/locations/us-central1/templates/one"}],"nextPageToken":"next"}`), nil
	})
	var out Snapshot
	c.CollectViewerModelArmor(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 1 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}

func TestViewerModelArmorSDPUnionAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		raw Object
		bad bool
	}{
		{Object{"basicConfig": Object{"filterEnforcement": "DISABLED"}}, false},
		{Object{"advancedConfig": Object{"inspectTemplate": "SECRET_SENTINEL", "deidentifyTemplate": "SECRET_SENTINEL"}}, false},
		{Object{"basicConfig": Object{"filterEnforcement": "DISABLED"}, "advancedConfig": Object{}}, true},
		{Object{"advancedConfig": nil}, true},
		{Object{"advancedConfig": Object{"inspectTemplate": true}}, true},
	} {
		safe, e := projectViewerModelArmor(Object{"filterConfig": Object{"sdpSettings": tc.raw}})
		if (e != nil) != tc.bad {
			t.Fatal(safe, e)
		}
		b, _ := json.Marshal(safe)
		if strings.Contains(string(b), "SECRET_SENTINEL") {
			t.Fatal("reference retained")
		}
		if tc.bad && safe["projection_complete"] != false {
			t.Fatal(safe)
		}
	}
}
