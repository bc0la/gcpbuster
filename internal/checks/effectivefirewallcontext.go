package checks

import "github.com/bc0la/gcpbuster/internal/inventory"

func effectiveFirewallContextEvidence(raw any, network string, observedRegion ...string) inventory.Object {
	out := inventory.Object{"status": "unknown", "effective_admission": "unknown", "scope": "global_and_hierarchical_only", "regional_policy_coverage": "not_collected"}
	d := obj(raw)
	regional := d["scope"] == "regional_global_and_hierarchical"
	validScope := d["scope"] == "global_and_hierarchical_only" && d["regional_policy_coverage"] == "not_collected"
	if regional && len(observedRegion) >= 1 && observedRegion[0] != "" && d["region"] == observedRegion[0] && d["regional_policy_coverage"] == "observed_response" {
		validScope = true
	}
	if d["network"] != network || !validScope || d["effective_admission"] != "unknown" {
		return out
	}
	status := s(d["status"])
	if status != "unknown" && status != "observed" && status != "partial" && status != "ambiguous" {
		return out
	}
	if status == "observed" || status == "partial" {
		for _, k := range []string{"classic_rule_count", "policy_count", "hierarchical_policy_count", "network_policy_count"} {
			n, ok := ingressContextInt(d[k], 10000)
			if !ok {
				return inventory.Object{"status": "unknown", "effective_admission": "unknown"}
			}
			out[k] = n
		}
		if out["hierarchical_policy_count"].(int)+out["network_policy_count"].(int) > out["policy_count"].(int) {
			return inventory.Object{"status": "unknown", "effective_admission": "unknown"}
		}
		if regional {
			n, ok := ingressContextInt(d["regional_policy_count"], 10000)
			if !ok || n+out["hierarchical_policy_count"].(int)+out["network_policy_count"].(int) > out["policy_count"].(int) {
				return inventory.Object{"status": "unknown", "effective_admission": "unknown"}
			}
			out["regional_policy_count"] = n
		}
	}
	out["status"] = status
	out["network"] = network
	if count, ok := ingressContextInt(d["unresolved_rule_count"], 100000); ok {
		out["unresolved_rule_count"] = count
	}
	candidates := []any{}
	if rows, ok := d["policy_rule_candidates"].([]any); ok && len(rows) <= 256 && (status == "observed" || status == "partial") {
		for _, raw := range rows {
			r := obj(raw)
			family, ok := ingressContextInt(r["ip_family"], 6)
			if !ok || len(observedRegion) < 2 || ((family != 4 || observedRegion[1] != "4") && (family != 6 || observedRegion[1] != "6")) {
				continue
			}
			index, ok := ingressContextInt(r["policy_index"], 9999)
			if !ok || index >= out["policy_count"].(int) {
				continue
			}
			priority, ok := ingressContextInt(r["rule_priority"], 2147483647)
			if !ok {
				continue
			}
			typ := s(r["policy_type"])
			if typ != "HIERARCHY" && typ != "NETWORK" && typ != "NETWORK_REGIONAL" && typ != "SYSTEM" && typ != "SYSTEM_GLOBAL" && typ != "SYSTEM_REGIONAL" && typ != "UNSPECIFIED" {
				continue
			}
			if !regional && (typ == "NETWORK_REGIONAL" || typ == "SYSTEM_REGIONAL") {
				continue
			}
			action := s(r["action"])
			if action != "allow" && action != "deny" && action != "goto_next" && action != "apply_security_profile_group" {
				continue
			}
			if r["target_match"] != "all_instances_on_observed_network" || r["source_match"] != "explicit_world_prefix" {
				continue
			}
			converted := []any{}
			for _, raw := range arr(r["layer4_configs"]) {
				l := obj(raw)
				converted = append(converted, inventory.Object{"IPProtocol": l["ipProtocol"], "ports": l["ports"]})
			}
			allowed, ok := ingressContextAllowed(converted)
			if !ok {
				continue
			}
			safe := inventory.Object{"policy_index": index, "policy_type": typ, "rule_priority": priority, "action": action, "ip_family": family, "protocols_ports": allowed, "target_match": "all_instances_on_observed_network", "source_match": "explicit_world_prefix", "assessment": "configured_policy_rule_candidate_not_effective_admission"}
			if typ != "HIERARCHY" {
				if p, ok := ingressContextInt(r["association_priority"], 2147483647); ok {
					safe["association_priority"] = p
				}
			}
			candidates = append(candidates, safe)
		}
	}
	out["policy_rule_candidates"] = candidates
	if regional {
		out["scope"] = "regional_global_and_hierarchical"
		out["region"] = observedRegion[0]
		out["regional_policy_coverage"] = "observed_response"
	}
	return out
}
