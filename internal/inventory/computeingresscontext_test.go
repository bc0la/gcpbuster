package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func ingressFixture() (Asset, Asset) {
	network := "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"
	rule := NewAsset("//compute.googleapis.com/projects/demo/global/firewalls/world", "compute.googleapis.com/Firewall", Object{"name": "world", "network": network, "direction": "INGRESS", "disabled": false, "sourceRanges": []any{"0.0.0.0/0"}, "targetTags": []any{"web"}, "allowed": []any{Object{"IPProtocol": "tcp", "ports": []any{"443"}}}, "priority": float64(1000)})
	vm := NewAsset("//compute.googleapis.com/projects/demo/zones/us-east1-b/instances/web", "compute.googleapis.com/Instance", Object{"name": "web", "tags": Object{"items": []any{"web"}}, "networkInterfaces": []any{Object{"network": network, "networkIP": "10.0.0.2", "accessConfigs": []any{Object{"natIP": "203.0.113.1"}}}}})
	return rule, vm
}
func TestComputeIngressExactNICAndTargets(t *testing.T) {
	r, v := ingressFixture()
	r.Resource.Data["sourceTags"] = []any{"source-tag"}
	r.Resource.Data["description"] = "SECRET_SENTINEL"
	s := Snapshot{Assets: []Asset{r, v}}
	CorrelateComputeIngressContext(&s)
	c := Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])
	if c["status"] != "configured_candidates" || c["effective_admission"] != "unknown" || len(List(c["matches"])) != 1 {
		t.Fatal(c)
	}
	m := Obj(List(c["matches"])[0])
	if m["target_match"] != "target_tag" {
		t.Fatal(m)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("description retained")
	}
}
func TestComputeIngressNegativeAndAmbiguousInputs(t *testing.T) {
	for _, mode := range []string{"network", "tag", "disabled", "egress", "denied", "malformed_sources", "bad_port", "destination_external_only", "duplicate", "no_external", "mixed_ip"} {
		r, v := ingressFixture()
		extra := []Asset{}
		switch mode {
		case "network":
			r.Resource.Data["network"] = "projects/other/global/networks/default"
		case "tag":
			r.Resource.Data["targetTags"] = []any{"different"}
		case "disabled":
			r.Resource.Data["disabled"] = true
		case "egress":
			r.Resource.Data["direction"] = "EGRESS"
		case "denied":
			r.Resource.Data["denied"] = []any{Object{"IPProtocol": "all"}}
		case "malformed_sources":
			r.Resource.Data["sourceRanges"] = nil
		case "bad_port":
			r.Resource.Data["allowed"] = []any{Object{"IPProtocol": "tcp", "ports": []any{"443-1"}}}
		case "destination_external_only":
			r.Resource.Data["destinationRanges"] = []any{"203.0.113.1/32"}
		case "duplicate":
			bad, _ := ingressFixture()
			bad.Resource.Data["disabled"] = true
			extra = append(extra, bad)
		case "no_external":
			delete(Obj(List(v.Resource.Data["networkInterfaces"])[0]), "accessConfigs")
		case "mixed_ip":
			r.Resource.Data["sourceRanges"] = []any{"0.0.0.0/0", "::/0"}
		}
		s := Snapshot{Assets: append([]Asset{r, v}, extra...)}
		CorrelateComputeIngressContext(&s)
		c := Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])
		if len(List(c["matches"])) != 0 || c["effective_admission"] != "unknown" {
			t.Fatal(mode, c)
		}
		if mode == "duplicate" && c["status"] != "partial" {
			t.Fatal(c)
		}
	}
}
func TestComputeIngressServiceAccountDefaultAndInternalDestination(t *testing.T) {
	r, v := ingressFixture()
	delete(r.Resource.Data, "targetTags")
	delete(r.Resource.Data, "sourceRanges")
	r.Resource.Data["targetServiceAccounts"] = []any{"web@demo.iam.gserviceaccount.com"}
	r.Resource.Data["destinationRanges"] = []any{"10.0.0.0/24"}
	v.Resource.Data["serviceAccounts"] = []any{Object{"email": "web@demo.iam.gserviceaccount.com"}}
	s := Snapshot{Assets: []Asset{r, v}}
	CorrelateComputeIngressContext(&s)
	c := Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])
	if len(List(c["matches"])) != 1 {
		t.Fatal(c)
	}
	m := Obj(List(c["matches"])[0])
	if m["destination_match"] != "explicit_nic_address" || m["target_match"] != "target_service_account" {
		t.Fatal(m)
	}
}

func TestComputeIngressConfiguredRoutesExactNetworkTagsAndAmbiguity(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_tag", "foreign", "nondefault", "ambiguous"} {
		r, v := ingressFixture()
		route := NewAsset("//compute.googleapis.com/projects/demo/global/routes/default-route", "compute.googleapis.com/Route", Object{"name": "default-route", "network": "projects/demo/global/networks/default", "destRange": "0.0.0.0/0", "nextHopGateway": "projects/demo/global/gateways/default-internet-gateway", "tags": []any{"web"}, "priority": float64(1000)})
		extra := []Asset{}
		switch mode {
		case "wrong_tag":
			route.Resource.Data["tags"] = []any{"other"}
		case "foreign":
			route.Resource.Data["network"] = "projects/other/global/networks/default"
		case "nondefault":
			route.Resource.Data["destRange"] = "192.0.2.0/24"
		case "ambiguous":
			copy := NewAsset(route.Name, route.Type, Object{"name": "default-route"})
			extra = append(extra, copy)
		}
		s := Snapshot{Assets: append([]Asset{r, v, route}, extra...)}
		CorrelateComputeIngressContext(&s)
		c := Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])
		want := 0
		if mode == "valid" {
			want = 1
		}
		if len(List(c["internet_gateway_routes"])) != want || c["effective_admission"] != "unknown" {
			t.Fatal(mode, c)
		}
	}
}

func TestComputeIngressSharedVPCIPv6AndMalformedDefaults(t *testing.T) {
	r, v := ingressFixture()
	v.Name = "//compute.googleapis.com/projects/service/zones/us-east1-b/instances/web"
	s := Snapshot{Assets: []Asset{r, v}}
	CorrelateComputeIngressContext(&s)
	if len(List(Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])["matches"])) != 1 {
		t.Fatal("explicit shared network not joined")
	}
	for _, mode := range []string{"numeric_alias_unresolved", "private_external", "ipv6_prefix_not_address", "disabled_null", "priority_fraction", "default_ipv4_only"} {
		r, v := ingressFixture()
		nic := Obj(List(v.Resource.Data["networkInterfaces"])[0])
		switch mode {
		case "numeric_alias_unresolved":
			nic["network"] = "projects/123/global/networks/default"
		case "private_external":
			nic["accessConfigs"] = []any{Object{"natIP": "10.0.0.3"}}
		case "ipv6_prefix_not_address":
			delete(nic, "accessConfigs")
			nic["ipv6AccessConfigs"] = []any{Object{"externalIpv6": "2001:db8::/96"}}
			r.Resource.Data["sourceRanges"] = []any{"::/0"}
		case "disabled_null":
			r.Resource.Data["disabled"] = nil
		case "priority_fraction":
			r.Resource.Data["priority"] = float64(1.5)
		case "default_ipv4_only":
			delete(r.Resource.Data, "sourceRanges")
			delete(nic, "accessConfigs")
			nic["ipv6AccessConfigs"] = []any{Object{"externalIpv6": "2001:db8::1"}}
		}
		s := Snapshot{Assets: []Asset{r, v}}
		CorrelateComputeIngressContext(&s)
		if len(List(Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])["matches"])) != 0 {
			t.Fatal(mode, s.Assets[1])
		}
	}
	r, v = ingressFixture()
	r.Resource.Data["sourceRanges"] = []any{"::/0"}
	nic := Obj(List(v.Resource.Data["networkInterfaces"])[0])
	delete(nic, "accessConfigs")
	nic["ipv6AccessConfigs"] = []any{Object{"externalIpv6": "2001:db8::1"}}
	s = Snapshot{Assets: []Asset{r, v}}
	CorrelateComputeIngressContext(&s)
	if len(List(Obj(s.Assets[1].Resource.Data["_gcpbusterComputeIngressContext"])["matches"])) != 1 {
		t.Fatal("IPv6 explicit address missing")
	}
}
