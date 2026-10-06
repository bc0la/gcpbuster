package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerAppEngineFirewallPaginationProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "appengine.googleapis.com" || r.URL.Path != "/v1/apps/demo/firewall/ingressRules" || r.URL.Query().Get("fields") != viewerAppEngineFirewallFields || r.URL.Query().Has("matchingAddress") {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"ingressRules":[{"priority":100,"action":"DENY","sourceRange":"1.2.3.4/24","description":"SOURCE_SENTINEL"}],"nextPageToken":"more"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "more" {
			t.Fatal(r.URL)
		}
		return response(200, `{"ingressRules":[{"priority":2147483647,"action":"ALLOW","sourceRange":"*"},{"priority":2,"action":"ALLOW","sourceRange":"2001:db8::1"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"appengine.applications.get": true}
	var s Snapshot
	c.CollectViewerAppEngineFirewall(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 1 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	d := s.Assets[0].Resource.Data
	rules := List(d["rules"])
	if d["complete"] != true || len(rules) != 3 || Obj(rules[0])["priority"] != 2 || Obj(rules[1])["sourceRange"] != "1.2.3.0/24" {
		t.Fatal(d)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("description leak")
	}
}
func TestViewerAppEngineFirewallPartialRetainsValid(t *testing.T) {
	for _, bad := range []string{`{"priority":0,"action":"ALLOW","sourceRange":"*"}`, `{"priority":2.5,"action":"ALLOW","sourceRange":"*"}`, `{"priority":3,"action":"BAD","sourceRange":"*"}`, `{"priority":3,"action":"ALLOW","sourceRange":"SOURCE_SENTINEL"}`, `{"priority":10,"action":"DENY","sourceRange":"*"}`, `null`} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return response(200, `{"ingressRules":[{"priority":10,"action":"ALLOW","sourceRange":"0/0"},`+bad+`],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"ingressRules":[{"priority":2147483647,"action":"DENY","sourceRange":"*"}]}`), nil
		})
		var s Snapshot
		c.CollectViewerAppEngineFirewall(context.Background(), &s, "demo", "projects/123")
		if calls != 2 || len(s.Assets) != 1 || s.Assets[0].Resource.Data["complete"] != false || len(List(s.Assets[0].Resource.Data["rules"])) != 2 || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}
func TestViewerAppEngineFirewallDenialAndMissingDefault(t *testing.T) {
	for _, body := range []string{`{}`, `{"ingressRules":null}`, `{"ingressRules":[{"priority":1,"action":"ALLOW","sourceRange":"*"}]}`, `{"ingressRules":[{"priority":2147483647,"action":"ALLOW","sourceRange":"0.0.0.0/0"}]}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.CollectViewerAppEngineFirewall(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 1 || s.Assets[0].Resource.Data["complete"] != false || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"ingressRules":[{"priority":1,"action":"DENY","sourceRange":"*"}],"nextPageToken":"next"}`), nil
		}
		return response(403, "SOURCE_SENTINEL"), nil
	})
	var s Snapshot
	c.CollectViewerAppEngineFirewall(context.Background(), &s, "demo", "projects/123")
	if len(List(s.Assets[0].Resource.Data["rules"])) != 1 || s.Assets[0].Resource.Data["complete"] != false {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{}
	before := calls
	s = Snapshot{}
	c.CollectViewerAppEngineFirewall(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
func TestViewerAppEngineFirewallGuard(t *testing.T) {
	endpoint := "https://appengine.googleapis.com/v1/apps/demo/firewall/ingressRules"
	valid := func() url.Values { return url.Values{"fields": {viewerAppEngineFirewallFields}, "pageSize": {"100"}} }
	if p, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || len(p) != 1 || p[0] != "appengine.applications.get" {
		t.Fatal(p, err)
	}
	for _, change := range []func(url.Values){func(q url.Values) { q.Set("matchingAddress", "1.2.3.4") }, func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Add("pageSize", "100") }, func(q url.Values) { q.Set("filter", "x") }} {
		q := valid()
		change(q)
		if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
			t.Fatal(q)
		}
	}
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		if _, err := viewerRequestPermissions(method, endpoint, valid()); err == nil {
			t.Fatal(method)
		}
	}
}
