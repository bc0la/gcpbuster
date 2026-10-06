package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerRunDomainsConditionalPermissionNoAliases(t *testing.T) {
	for _, permissions := range []map[string]bool{{}, {"run.routes.list": true}, {"run.googleapis.com/domainmappings.list": true}} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			t.Fatal("unverified baseline reached transport", r.URL)
			return nil, nil
		})
		c.viewerPolicy.permissions = permissions
		var out Snapshot
		c.CollectViewerRunDomains(context.Background(), &out, "demo", "projects/123", "us-central1")
		if len(out.Assets) != 0 || len(out.Coverage) != 1 || out.Coverage[0].Status != "incomplete" {
			t.Fatal(out)
		}
	}
}

// Positive transport fixtures simulate a future freshly fetched three-role
// definition containing the exact literal. They do NOT assert today's Viewer
// includes it; actual/default baseline tests above deliberately omit it.
func TestViewerRunDomainsConditionalPaginationProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "us-central1-run.googleapis.com" || r.URL.Path != "/apis/domains.cloudrun.com/v1/namespaces/demo/domainmappings" || r.URL.Query().Get("fields") != viewerRunDomainFields || r.URL.Query().Get("limit") != "100" {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"items":[{"metadata":{"name":"wrong.example.com","namespace":"foreign"}}],"metadata":{"continue":"next"}}`), nil
		}
		if r.URL.Query().Get("continue") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":[{"metadata":{"name":"api.example.com","namespace":"123","generation": "4","labels":{"secret":"SENTINEL"}},"spec":{"routeName":"service"},"status":{"observedGeneration":4,"mappedRouteName":"service","conditions":[{"type":"Ready","status":"False","reason":"SENTINEL","message":"SENTINEL"}],"resourceRecords":[{"type":"CNAME","name":"api","rrdata":"ghs.googlehosted.com."},{"type":"TXT","rrdata":"SENTINEL"}]}}]}`), nil
	})
	c.viewerPolicy.permissions["run.domainmappings.list"] = true
	var out Snapshot
	c.CollectViewerRunDomains(context.Background(), &out, "demo", "projects/123", "us-central1")
	if calls != 2 || len(out.Assets) != 1 {
		t.Fatal(out)
	}
	d := out.Assets[0].Resource.Data
	if Str(d["_gcpbusterServiceReference"]) != "//run.googleapis.com/projects/demo/locations/us-central1/services/service" || Str(Obj(d["metadata"])["generation"]) != "4" {
		t.Fatal(d)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal("unsafe source retained")
	}
	if !hasCoverage(out, "failed") {
		t.Fatal("partial input not reported")
	}
}

func TestViewerRunDomainsStrictRegionalGuardAndLateDenial(t *testing.T) {
	endpoint := "https://us-central1-run.googleapis.com/apis/domains.cloudrun.com/v1/namespaces/demo/domainmappings"
	q := url.Values{"fields": {viewerRunDomainFields}, "limit": {"100"}}
	for _, tc := range []struct {
		method, endpoint string
		q                url.Values
	}{{"POST", endpoint, q}, {"GET", strings.Replace(endpoint, "us-central1-run", "run", 1), q}, {"GET", endpoint + "/api.example.com", q}, {"GET", strings.Replace(endpoint, "-run.googleapis.com", "-run.googleapis.com.evil.example", 1), q}, {"GET", endpoint, url.Values{"fields": {viewerRunDomainFields}, "limit": {"100"}, "watch": {"true"}}}, {"GET", endpoint, url.Values{"fields": {"*"}, "limit": {"100"}}}} {
		if _, err := viewerRequestPermissions(tc.method, tc.endpoint, tc.q); err == nil {
			t.Fatal("allowed", tc.endpoint)
		}
	}
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"items":[{"metadata":{"name":"api.example.com","namespace":"demo"},"spec":{"routeName":"service"}}],"metadata":{"continue":"next"}}`), nil
		}
		return response(403, `SECRET`), nil
	})
	c.viewerPolicy.permissions["run.domainmappings.list"] = true
	var out Snapshot
	c.CollectViewerRunDomains(context.Background(), &out, "demo", "projects/123", "us-central1")
	if calls != 2 || len(out.Assets) != 1 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
