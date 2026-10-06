package inventory

import "testing"

func TestClassicDenyPriorityCoverageAndPortUnion(t *testing.T) {
	for _, mode := range []string{"tie", "higher", "lower", "ports_partial", "ports_union", "missing_coverage", "failed_coverage", "wrong_target", "narrow_source", "conflict", "higher_alternative_allow"} {
		allow, vm := ingressFixture()
		allow.Resource.Data["allowed"] = []any{Object{"IPProtocol": "tcp", "ports": []any{"80-90"}}}
		deny, _ := ingressFixture()
		deny.Name = "//compute.googleapis.com/projects/demo/global/firewalls/deny"
		deny.Resource.Data["name"] = "deny"
		delete(deny.Resource.Data, "allowed")
		deny.Resource.Data["denied"] = []any{Object{"IPProtocol": "6", "ports": []any{"80-90"}}}
		extra := []Asset{}
		status := "definitely_shadowed_by_observed_classic_deny"
		coverage := []Coverage{{Source: "viewer-compute-firewalls:demo", Status: "completed"}}
		switch mode {
		case "higher":
			deny.Resource.Data["priority"] = float64(900)
		case "lower":
			deny.Resource.Data["priority"] = float64(1001)
			status = "unknown"
		case "ports_partial":
			deny.Resource.Data["denied"] = []any{Object{"IPProtocol": "tcp", "ports": []any{"80"}}}
			status = "observed_overlap"
		case "ports_union":
			deny.Resource.Data["denied"] = []any{Object{"IPProtocol": "tcp", "ports": []any{"80-84", "85-90"}}}
		case "missing_coverage":
			coverage = nil
			status = "observed_overlap"
		case "failed_coverage":
			coverage = append(coverage, Coverage{Source: "viewer-compute-firewalls:demo", Status: "failed"})
			status = "observed_overlap"
		case "wrong_target":
			deny.Resource.Data["targetTags"] = []any{"other"}
			status = "unknown"
		case "narrow_source":
			deny.Resource.Data["sourceRanges"] = []any{"192.0.2.0/24"}
			status = "unknown"
		case "conflict":
			other, _ := ingressFixture()
			other.Name = deny.Name
			other.Resource.Data["name"] = "deny"
			extra = append(extra, other)
			status = "unknown"
		case "higher_alternative_allow":
			other, _ := ingressFixture()
			other.Name = "//compute.googleapis.com/projects/demo/global/firewalls/alternate"
			other.Resource.Data["name"] = "alternate"
			other.Resource.Data["priority"] = float64(1)
			extra = append(extra, other)
		}
		s := Snapshot{Assets: append([]Asset{allow, deny, vm}, extra...), Coverage: coverage}
		CorrelateComputeIngressContext(&s)
		matches := List(Obj(s.Assets[2].Resource.Data["_gcpbusterComputeIngressContext"])["matches"])
		var c Object
		for _, raw := range matches {
			r := Obj(raw)
			if r["firewall_resource"] == allow.Name {
				c = Obj(r["classic_deny_context"])
			}
		}
		if c["status"] != status || c["effective_admission"] != "unknown" {
			t.Fatal(mode, c)
		}
		if len(matches) == 0 {
			t.Fatal("exposure suppressed")
		}
	}
}
func TestClassicDenyDestinationAndProtocolConservatism(t *testing.T) {
	a, _ := ingressFixture()
	c, ok := parseIngressCandidate(a)
	if !ok {
		t.Fatal("fixture")
	}
	d := c
	d.asset.Name = "//compute.googleapis.com/projects/demo/global/firewalls/deny"
	d.allowed = []any{Object{"IPProtocol": "udp", "ports": []any{"443"}}}
	got := classicDenyContext(c, []ingressCandidate{d}, Object{}, []string{"web"}, nil, true, true, true)
	if got["status"] != "unknown" {
		t.Fatal(got)
	}
	overlap, covered := classicProtocolPortRelation([]any{Object{"IPProtocol": "all", "ports": []any{}}}, []any{Object{"IPProtocol": "tcp", "ports": []any{}}})
	if !overlap || covered {
		t.Fatal(overlap, covered)
	}
	_, covered = classicProtocolPortRelation([]any{Object{"IPProtocol": "tcp", "ports": []any{"80-90"}}}, []any{Object{"IPProtocol": "all", "ports": []any{}}})
	if !covered {
		t.Fatal("all protocol coverage")
	}
}
