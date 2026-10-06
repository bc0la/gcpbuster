package inventory

import "net/netip"

// Only explicit world-source, untargeted instance rules with no unresolved
// dynamic selectors are candidates. Association and goto_next ordering are not
// interpreted. Empty output never means that the network lacks policy rules.
func effectivePolicyCandidates(policies []any, network string) ([]any, int) {
	out := []any{}
	unknown := 0
	total := 0
	for pi, raw := range policies {
		p := Obj(raw)
		typ := Str(p["type"])
		rules := List(p["rules"])
		if len(rules) > 10000 || total+len(rules) > 10000 {
			return out, unknown + 1
		}
		total += len(rules)
		priorities := map[int]int{}
		for _, raw := range rules {
			if n, ok := effectiveFirewallInteger(Obj(raw)["priority"], 2147483647); ok {
				priorities[n]++
			}
		}
		for _, raw := range rules {
			d := Obj(raw)
			if d["projection_complete"] == false {
				unknown++
				continue
			}
			if d["direction"] != "INGRESS" {
				continue
			}
			if disabled, exists := d["disabled"]; exists {
				b, ok := disabled.(bool)
				if !ok {
					unknown++
					continue
				}
				if b {
					continue
				}
			}
			priority, ok := effectiveFirewallInteger(d["priority"], 2147483647)
			if !ok || priorities[priority] != 1 {
				unknown++
				continue
			}
			action := Str(d["action"])
			if action != "allow" && action != "deny" && action != "goto_next" && action != "apply_security_profile_group" {
				unknown++
				continue
			}
			if target, exists := d["targetType"]; exists && target != "INSTANCES" {
				unknown++
				continue
			}
			if len(List(d["targetSecureTags"])) > 0 || len(List(d["targetServiceAccounts"])) > 0 {
				unknown++
				continue
			}
			targets := List(d["targetResources"])
			if len(targets) > 0 {
				match := false
				for _, t := range targets {
					if Str(t) == network {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			m := Obj(d["match"])
			if m == nil {
				unknown++
				continue
			}
			complex := false
			for k, v := range m {
				switch k {
				case "srcIpRanges", "destIpRanges", "layer4Configs":
				case "srcSecureTags":
					if len(List(v)) > 0 {
						complex = true
					}
				case "srcNetworkType", "destNetworkType", "srcNetworkContext", "destNetworkContext":
					if v != "UNSPECIFIED" {
						complex = true
					}
				default:
					if n, ok := effectiveFirewallInteger(v, 10000); !ok || n != 0 {
						complex = true
					}
				}
			}
			if complex {
				unknown++
				continue
			}
			families := map[int]bool{}
			valid := true
			sourceFamily := 0
			for _, raw := range List(m["srcIpRanges"]) {
				prefix, e := netip.ParsePrefix(Str(raw))
				if e != nil || prefix.Addr().Is4In6() {
					valid = false
					break
				}
				family := 6
				if prefix.Addr().Is4() {
					family = 4
				}
				if sourceFamily != 0 && sourceFamily != family {
					valid = false
				}
				sourceFamily = family
				if prefix.Bits() == 0 {
					families[family] = true
				}
			}
			layer4, ok := effectiveLayer4(m["layer4Configs"], "ipProtocol")
			if !ok || len(layer4) == 0 || !valid || len(families) != 1 {
				unknown++
				continue
			}
			family := 4
			if families[6] {
				family = 6
			}
			dest := List(m["destIpRanges"])
			if len(dest) > 0 {
				world := false
				for _, raw := range dest {
					prefix, e := netip.ParsePrefix(Str(raw))
					if e != nil || prefix.Addr().Is4In6() || (family == 4 && !prefix.Addr().Is4()) || (family == 6 && !prefix.Addr().Is6()) {
						valid = false
						continue
					}
					if prefix.Bits() == 0 && ((family == 4 && prefix.Addr().Is4()) || (family == 6 && prefix.Addr().Is6() && !prefix.Addr().Is4In6())) {
						world = true
					}
				}
				if !world || !valid {
					unknown++
					continue
				}
			}
			if len(out) >= 256 {
				unknown++
				continue
			}
			c := Object{"policy_index": pi, "policy_type": typ, "rule_priority": priority, "action": action, "ip_family": family, "layer4_configs": layer4, "target_match": "all_instances_on_observed_network", "source_match": "explicit_world_prefix", "assessment": "configured_policy_rule_candidate_not_effective_admission"}
			if typ != "HIERARCHY" {
				if priority, ok := effectiveFirewallInteger(p["priority"], 2147483647); ok {
					c["association_priority"] = priority
				}
			}
			out = append(out, c)
		}
	}
	return out, unknown
}
