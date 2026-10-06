package inventory

import (
	"reflect"
	"regexp"
	"strings"
)

func computeNICRegion(nic Object) string {
	s := Str(nic["subnetwork"])
	for _, p := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		s = strings.TrimPrefix(s, p)
	}
	m := regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/regions/([a-z][a-z0-9-]*)/subnetworks/[a-z][-a-z0-9]*$`).FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func effectiveNetworkFirewallContexts(snap *Snapshot) map[string]Object {
	out := map[string]Object{}
	conflict := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != EffectiveNetworkFirewallsType && a.Type != EffectiveRegionalNetworkFirewallsType {
			continue
		}
		d := a.Resource.Data
		network := Str(d["network"])
		if len(network) < len("//compute.googleapis.com/") || network[:len("//compute.googleapis.com/")] != "//compute.googleapis.com/" {
			continue
		}
		short := network[len("//compute.googleapis.com/"):]
		key := short
		expected := network + "/effectiveFirewalls"
		scope := "global_and_hierarchical_only"
		regional := a.Type == EffectiveRegionalNetworkFirewallsType
		region := ""
		if regional {
			region = Str(d["region"])
			if !viewerLocation.MatchString(region) {
				continue
			}
			key += "|" + region
			expected += "/" + region
			scope = "regional_global_and_hierarchical"
		}
		if ingressNetwork(short) != short || a.Name != expected || d["scope"] != scope || d["effective_admission"] != "unknown" {
			continue
		}
		complete, ok := d["complete"].(bool)
		if !ok {
			continue
		}
		classics, ce := viewerRows(d, "firewalls")
		policies, pe := viewerRows(d, "firewallPolicys")
		if ce != nil || pe != nil || len(classics) > 10000 || len(policies) > 10000 {
			continue
		}
		context := Object{"network": network, "status": "observed", "scope": "global_and_hierarchical_only", "classic_rule_count": len(classics), "policy_count": len(policies), "hierarchical_policy_count": 0, "network_policy_count": 0, "regional_policy_coverage": "not_collected", "effective_admission": "unknown"}
		if regional {
			context["scope"] = scope
			context["region"] = region
			context["regional_policy_coverage"] = "observed_response"
			context["regional_policy_count"] = 0
		}
		if !complete {
			context["status"] = "partial"
		}
		policyCandidates, unknownRules := effectivePolicyCandidates(policies, short)
		context["policy_rule_candidates"] = policyCandidates
		context["unresolved_rule_count"] = unknownRules
		for _, raw := range policies {
			p := Obj(raw)
			switch p["type"] {
			case "HIERARCHY":
				context["hierarchical_policy_count"] = context["hierarchical_policy_count"].(int) + 1
			case "NETWORK":
				context["network_policy_count"] = context["network_policy_count"].(int) + 1
			case "NETWORK_REGIONAL":
				if regional {
					context["regional_policy_count"] = context["regional_policy_count"].(int) + 1
				} else {
					context["status"] = "partial"
				}
			case "SYSTEM_GLOBAL", "SYSTEM_REGIONAL":
				if !regional {
					context["status"] = "partial"
				}
			case "SYSTEM", "UNSPECIFIED":
			default:
				context["status"] = "partial"
			}
		}
		if old := out[key]; old != nil && !reflect.DeepEqual(old, context) {
			conflict[key] = true
		}
		out[key] = context
	}
	for key := range conflict {
		out[key]["status"] = "ambiguous"
		out[key]["policy_rule_candidates"] = []any{}
	}
	return out
}
