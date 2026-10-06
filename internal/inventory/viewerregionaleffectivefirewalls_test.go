package inventory

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestViewerRegionalEffectiveFirewallExactObservedNetworkRegion(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/compute/v1/projects/demo/regions/us-east1/firewallPolicies/getEffectiveFirewalls" || r.URL.Query().Get("network") != "projects/demo/global/networks/default" || r.URL.Query().Get("fields") != viewerEffectiveFirewallFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"firewallPolicys":[{"type":"NETWORK_REGIONAL","priority":100,"rules":[{"priority":1,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["22"]}]}}]}]}`), nil
	})
	subnet := NewAsset("//compute.googleapis.com/projects/demo/regions/us-east1/subnetworks/subnet", "compute.googleapis.com/Subnetwork", Object{"name": "subnet", "network": "projects/demo/global/networks/default"})
	out := Snapshot{Assets: []Asset{subnet}}
	c.CollectViewerRegionalEffectiveFirewalls(context.Background(), &out, "demo", "projects/123")
	if calls != 1 || len(out.Assets) != 2 || hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	d := out.Assets[1].Resource.Data
	if d["scope"] != "regional_global_and_hierarchical" || d["region"] != "us-east1" || d["complete"] != true {
		t.Fatal(d)
	}
	context := effectiveNetworkFirewallContexts(&out)["projects/demo/global/networks/default|us-east1"]
	if context["regional_policy_count"] != 1 || context["regional_policy_coverage"] != "observed_response" {
		t.Fatal(context)
	}
}
func TestViewerRegionalEffectiveFirewallGuardForeignNetwork(t *testing.T) {
	ep := "https://compute.googleapis.com/compute/v1/projects/demo/regions/us-east1/firewallPolicies/getEffectiveFirewalls"
	q := url.Values{"fields": {viewerEffectiveFirewallFields}, "network": {"projects/demo/global/networks/default"}}
	p, e := viewerRequestPermissions("GET", ep, q)
	if e != nil || len(p) != 1 || p[0] != "compute.networks.getRegionEffectiveFirewalls" {
		t.Fatal(p, e)
	}
	q.Set("network", "projects/other/global/networks/default")
	if _, e := viewerRequestPermissions("GET", ep, q); e == nil {
		t.Fatal("foreign allowed")
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network"); return nil, nil })
	delete(c.viewerPolicy.permissions, "compute.networks.getRegionEffectiveFirewalls")
	subnet := NewAsset("//compute.googleapis.com/projects/demo/regions/us-east1/subnetworks/subnet", "compute.googleapis.com/Subnetwork", Object{"name": "subnet", "network": "projects/demo/global/networks/default"})
	out := Snapshot{Assets: []Asset{subnet}}
	c.CollectViewerRegionalEffectiveFirewalls(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}

func TestEffectivePolicyOnlyNICContextWithoutClassicAllows(t *testing.T) {
	_, vm := ingressFixture()
	nic := Obj(List(vm.Resource.Data["networkInterfaces"])[0])
	nic["subnetwork"] = "projects/demo/regions/us-east1/subnetworks/subnet"
	for _, action := range []string{"allow", "deny", "goto_next"} {
		raw := Object{"firewallPolicys": []any{Object{"type": "NETWORK_REGIONAL", "priority": float64(100), "rules": []any{Object{"priority": float64(1), "action": action, "direction": "INGRESS", "match": Object{"srcIpRanges": []any{"0.0.0.0/0"}, "layer4Configs": []any{Object{"ipProtocol": "tcp", "ports": []any{"443"}}}}}}}}}
		d, e := projectEffectiveFirewallScope(raw, "projects/demo/global/networks/default", true)
		if e != nil {
			t.Fatal(e)
		}
		d["region"] = "us-east1"
		a := NewAsset("//compute.googleapis.com/projects/demo/global/networks/default/effectiveFirewalls/us-east1", EffectiveRegionalNetworkFirewallsType, d)
		s := Snapshot{Assets: []Asset{vm, a}}
		CorrelateComputeIngressContext(&s)
		c := Obj(s.Assets[0].Resource.Data["_gcpbusterComputeIngressContext"])
		if len(List(c["matches"])) != 0 || len(List(c["effective_policy_contexts"])) != 1 {
			t.Fatal(c)
		}
		context := Obj(Obj(List(c["effective_policy_contexts"])[0])["context"])
		rules := List(context["policy_rule_candidates"])
		if len(rules) != 1 || Obj(rules[0])["action"] != action {
			t.Fatal(context)
		}
	}
}
