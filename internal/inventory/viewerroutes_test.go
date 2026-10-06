package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerRoutesScopedPaginationAndRedaction(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/compute/v1/projects/demo/global/routes" || r.URL.Query().Get("fields") != viewerRouteFields || r.URL.Query().Get("maxResults") != "100" {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"items":[{"name":"foreign","network":"projects/other/global/networks/default","destRange":"0.0.0.0/0"},{"name":"internet","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","destRange":"0.0.0.0/0","priority":1000,"nextHopGateway":"https://www.googleapis.com/compute/v1/projects/demo/global/gateways/default-internet-gateway","routeType":"STATIC","description":"SECRET_SENTINEL","nextHopInstance":"SECRET_SENTINEL"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":[{"name":"ipv6","network":"projects/123/global/networks/default","destRange":"::/0","tags":["web"]}]}`), nil
	})
	var out Snapshot
	c.CollectViewerRoutes(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 2 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[0].Resource.Data["nextHopGateway"] != "projects/demo/global/gateways/default-internet-gateway" || out.Assets[1].Resource.Data["nextHopGateway"] != nil {
		t.Fatal(out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("extra source retained")
	}
}
func TestViewerRoutesGuardBaselineAndLateFailure(t *testing.T) {
	ep := "https://compute.googleapis.com/compute/v1/projects/demo/global/routes"
	q := url.Values{"fields": {viewerRouteFields}, "maxResults": {"100"}}
	p, e := viewerRequestPermissions("GET", ep, q)
	if e != nil || len(p) != 1 || p[0] != "compute.routes.list" {
		t.Fatal(p, e)
	}
	if _, e := viewerRequestPermissions("POST", ep, q); e == nil {
		t.Fatal("write")
	}
	q.Set("fields", "*")
	if _, e := viewerRequestPermissions("GET", ep, q); e == nil {
		t.Fatal("fields")
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("pageToken") != "" {
			return response(403, `denied`), nil
		}
		return response(200, `{"items":[{"name":"one","network":"projects/demo/global/networks/default","destRange":"0.0.0.0/0"}],"nextPageToken":"next"}`), nil
	})
	var out Snapshot
	c.CollectViewerRoutes(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 1 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	c = testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network"); return nil, nil })
	delete(c.viewerPolicy.permissions, "compute.routes.list")
	out = Snapshot{}
	c.CollectViewerRoutes(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}

func TestViewerRoutesMalformedSelectorsCannotBecomeDefaults(t *testing.T) {
	for _, field := range []string{`"tags":null`, `"priority":"1000"`, `"tags":[false]`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"items":[{"name":"internet","network":"projects/demo/global/networks/default","destRange":"0.0.0.0/0","nextHopGateway":"projects/demo/global/gateways/default-internet-gateway",`+field+`}]}`), nil
		})
		_, vm := ingressFixture()
		out := Snapshot{Assets: []Asset{vm}}
		c.CollectViewerRoutes(context.Background(), &out, "demo", "projects/123")
		CorrelateComputeIngressContext(&out)
		if out.Assets[1].Resource.Data["projection_complete"] != false || len(List(Obj(out.Assets[0].Resource.Data["_gcpbusterComputeIngressContext"])["internet_gateway_routes"])) != 0 {
			t.Fatal(out)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"items":[{"name":"internet","network":"projects/demo/global/networks/default","destRange":"0.0.0.0/0","nextHopGateway":"projects/demo/global/gateways/default-internet-gateway"},{"name":"internet","network":"projects/demo/global/networks/default","destRange":"10.0.0.0/8"}]}`), nil
	})
	var out Snapshot
	c.CollectViewerRoutes(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 1 || out.Assets[0].Resource.Data["projection_complete"] != false {
		t.Fatal(out)
	}
}
