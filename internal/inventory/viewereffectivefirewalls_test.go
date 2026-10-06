package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerEffectiveFirewallsScopedProjectionAndRuleTypes(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/compute/v1/projects/demo/global/networks/default/getEffectiveFirewalls" || r.URL.Query().Get("fields") != viewerEffectiveFirewallFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"firewalls":[{"name":"world","network":"projects/demo/global/networks/default","direction":"INGRESS","priority":1000,"allowed":[{"IPProtocol":"tcp","ports":["443"]}],"sourceRanges":["0.0.0.0/0"],"description":"SENSITIVE_SENTINEL"}],"firewallPolicys":[{"type":"HIERARCHY","name":"SENSITIVE_SENTINEL","rules":[{"priority":1,"action":"deny","direction":"INGRESS","disabled":false,"targetSecureTags":[{"name":"tagValues/123","state":"EFFECTIVE"}],"match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["22"]}],"srcFqdns":["SENSITIVE_SENTINEL"]}}]}]}`), nil
	})
	net := NewAsset("//compute.googleapis.com/projects/demo/global/networks/default", "compute.googleapis.com/Network", Object{"name": "default"})
	foreign := NewAsset("//compute.googleapis.com/projects/other/global/networks/foreign", "compute.googleapis.com/Network", Object{"name": "foreign"})
	out := Snapshot{Assets: []Asset{net, foreign}}
	c.CollectViewerEffectiveFirewalls(context.Background(), &out, "demo", "projects/123")
	if calls != 1 || len(out.Assets) != 3 || hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	d := out.Assets[2].Resource.Data
	if d["complete"] != true || d["effective_admission"] != "unknown" || d["scope"] != "global_and_hierarchical_only" {
		t.Fatal(d)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "SENSITIVE_SENTINEL") {
		t.Fatal("source retained")
	}
}
func TestViewerEffectiveFirewallsMalformedRowsPreservedPartial(t *testing.T) {
	raw := Object{"firewallPolicys": []any{Object{"type": "NETWORK", "rules": []any{Object{"action": "deny", "priority": "1"}, Object{"action": "goto_next", "priority": float64(2147483647), "match": Object{"srcIpRanges": []any{"::/0"}}}}}, nil}}
	d, e := projectEffectiveFirewalls(raw, "projects/demo/global/networks/default")
	if e == nil || d["complete"] != false || len(List(d["firewallPolicys"])) != 2 || len(List(Obj(List(d["firewallPolicys"])[0])["rules"])) != 2 {
		t.Fatal(d, e)
	}
}
func TestViewerEffectiveFirewallsGuardDenialAndDuplicateScope(t *testing.T) {
	ep := "https://compute.googleapis.com/compute/v1/projects/demo/global/networks/default/getEffectiveFirewalls"
	q := url.Values{"fields": {viewerEffectiveFirewallFields}}
	p, e := viewerRequestPermissions("GET", ep, q)
	if e != nil || len(p) != 1 || p[0] != "compute.networks.getEffectiveFirewalls" {
		t.Fatal(p, e)
	}
	for _, bad := range []url.Values{{"fields": {"*"}}, {"fields": {viewerEffectiveFirewallFields}, "filter": {"x"}}} {
		if _, e := viewerRequestPermissions("GET", ep, bad); e == nil {
			t.Fatal(bad)
		}
	}
	if _, e := viewerRequestPermissions("POST", ep, q); e == nil {
		t.Fatal("write")
	}
	net := NewAsset("//compute.googleapis.com/projects/demo/global/networks/default", "compute.googleapis.com/Network", Object{"name": "default"})
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network"); return nil, nil })
	out := Snapshot{Assets: []Asset{net, net}}
	c.CollectViewerEffectiveFirewalls(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	delete(c.viewerPolicy.permissions, "compute.networks.getEffectiveFirewalls")
	out = Snapshot{Assets: []Asset{net}}
	c.CollectViewerEffectiveFirewalls(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
