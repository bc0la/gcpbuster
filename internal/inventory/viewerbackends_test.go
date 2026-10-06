package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerBackendServicesGlobalRegionalPaginationAndProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/compute/v1/projects/demo/aggregated/backendServices" || r.URL.Query().Get("fields") != viewerBackendServiceFields || r.URL.Query().Get("returnPartialSuccess") != "true" {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"items":{"global":{"backendServices":[{"name":"wrong","selfLink":"https://compute.googleapis.com/compute/v1/projects/foreign/global/backendServices/wrong"},{"name":"global-web","protocol":"HTTPS","loadBalancingScheme":"EXTERNAL_MANAGED","iap":{"enabled":false,"oauth2ClientSecret":"SENTINEL"},"description":"SENTINEL"}]},"zones/us-central1-a":{"backendServices":[{"name":"invalid"}]}},"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":{"regions/us-central1":{"backendServices":[{"name":"regional-web","selfLink":"https://www.googleapis.com/compute/v1/projects/123/regions/us-central1/backendServices/regional-web","region":"https://compute.googleapis.com/compute/v1/projects/123/regions/us-central1","protocol":"HTTP","loadBalancingScheme":"INTERNAL_MANAGED","iap":{"enabled":true},"backends":[{"group":"SENTINEL"}]}]},"regions/us-east1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}}}`), nil
	})
	var out Snapshot
	c.CollectViewerBackendServices(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 2 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[0].Type != "compute.googleapis.com/BackendService" || out.Assets[1].Type != "compute.googleapis.com/RegionBackendService" || out.Assets[1].Resource.Location != "us-central1" {
		t.Fatal(out.Assets)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal("unsafe metadata retained")
	}
}

func TestViewerBackendServicesLateFailureAndUnknownFlags(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"items":{"global":{"backendServices":[{"name":"unknown","protocol":"HTTP","iap":{"enabled":"false"}},{"name":"missing","protocol":"HTTPS"}]}},"nextPageToken":"next"}`), nil
		}
		return response(403, `SENTINEL`), nil
	})
	var out Snapshot
	c.CollectViewerBackendServices(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 2 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	for _, a := range out.Assets {
		if a.Resource.Data["iap"] != nil {
			t.Fatal("unknown=>disabled", a)
		}
	}
}

func TestViewerBackendServicesStrictGuardAndRoleGate(t *testing.T) {
	endpoint := "https://compute.googleapis.com/compute/v1/projects/demo/aggregated/backendServices"
	q := url.Values{"fields": {viewerBackendServiceFields}, "maxResults": {"100"}, "returnPartialSuccess": {"true"}}
	p, e := viewerRequestPermissions("GET", endpoint, q)
	if e != nil || len(p) != 1 || p[0] != "compute.backendServices.list" {
		t.Fatal(p, e)
	}
	for _, tc := range []struct {
		method, path string
		q            url.Values
	}{{"POST", endpoint, q}, {"GET", endpoint, url.Values{"fields": {"*"}, "maxResults": {"100"}, "returnPartialSuccess": {"true"}}}, {"GET", endpoint, url.Values{"fields": {viewerBackendServiceFields}, "maxResults": {"100"}, "returnPartialSuccess": {"true"}, "filter": {"x"}}}, {"POST", "https://compute.googleapis.com/compute/v1/projects/demo/global/backendServices/backend/getHealth", nil}} {
		if _, e := viewerRequestPermissions(tc.method, tc.path, tc.q); e == nil {
			t.Fatal(tc)
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("missing baseline reached transport")
		return nil, nil
	})
	delete(c.viewerPolicy.permissions, "compute.backendServices.list")
	var out Snapshot
	c.CollectViewerBackendServices(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") || len(out.Assets) != 0 {
		t.Fatal(out)
	}
}

func TestViewerBackendServiceIDsTypedAndPartial(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("fields") != viewerBackendServiceFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":{"global":{"backendServices":[{"name":"one","id":"18446744073709551615","iap":{"enabled":true}},{"name":"two","id":42},{"name":"three","id":"18446744073709551616"},{"name":"four"}]}}}`), nil
	})
	var out Snapshot
	c.CollectViewerBackendServices(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 4 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[0].Resource.Data["id"] != "18446744073709551615" {
		t.Fatal(out)
	}
	for _, a := range out.Assets[1:] {
		if a.Resource.Data["id"] != nil {
			t.Fatal(a)
		}
	}
}
