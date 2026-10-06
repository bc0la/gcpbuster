package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const EffectiveNetworkFirewallsType = "gcpbuster.googleapis.com/EffectiveNetworkFirewalls"
const EffectiveRegionalNetworkFirewallsType = "gcpbuster.googleapis.com/EffectiveRegionalNetworkFirewalls"
const viewerEffectiveFirewallFields = "firewalls(name,network,direction,priority,disabled,sourceRanges,destinationRanges,sourceTags,targetTags,sourceServiceAccounts,targetServiceAccounts,allowed(IPProtocol,ports),denied(IPProtocol,ports)),firewallPolicys(type,priority,rules(priority,action,direction,disabled,targetType,targetResources,targetServiceAccounts,targetSecureTags(name,state),match(srcIpRanges,destIpRanges,layer4Configs(ipProtocol,ports),srcSecureTags(name,state),srcNetworkType,destNetworkType,srcNetworkContext,destNetworkContext,srcFqdns,destFqdns,srcAddressGroups,destAddressGroups,srcRegionCodes,destRegionCodes,srcThreatIntelligences,destThreatIntelligences,srcNetworks)))"

func (c *Client) CollectViewerEffectiveFirewalls(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-effective-firewalls:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	names := map[string]bool{}
	bad := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "compute.googleapis.com/Network" {
			continue
		}
		name := Str(a.Resource.Data["name"])
		if !backendID.MatchString(name) || len(name) > 63 {
			continue
		}
		valid := a.Name == "//compute.googleapis.com/projects/"+projectID+"/global/networks/"+name || a.Name == "//compute.googleapis.com/"+number+"/global/networks/"+name
		if !valid {
			continue
		}
		if names[name] {
			bad[name] = true
		}
		names[name] = true
	}
	keys := []string{}
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for i, name := range keys {
		if i >= 1024 {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-effective-firewalls:bounds:" + projectID, Status: "incomplete", Error: "Observed network count exceeds bounded collection"})
			break
		}
		if bad[name] {
			out.record("viewer-effective-firewalls:ambiguous:"+name, 0, fmt.Errorf("duplicate network identity"))
			continue
		}
		network := "projects/" + projectID + "/global/networks/" + name
		d, e := c.get(ctx, "https://compute.googleapis.com/compute/v1/"+network+"/getEffectiveFirewalls", url.Values{"fields": {viewerEffectiveFirewallFields}})
		count := 0
		if e == nil {
			safe, pe := projectEffectiveFirewalls(d, network)
			e = pe
			a := NewAsset("//compute.googleapis.com/"+network+"/effectiveFirewalls", EffectiveNetworkFirewallsType, safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			count = 1
		}
		out.record("viewer-effective-firewalls:"+network, count, e)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-effective-firewalls:limitations:" + projectID, Status: "notice", Error: "Network getEffectiveFirewalls returns classic, global network and hierarchical policy configuration, not regional network firewall policies. Selected typed rules and association priorities only; secure-tag membership, dynamic/FQDN/address-group selectors, goto_next ordering, security-profile actions and actual connection admission are not evaluated. No probes, rule changes, logs or packet data are accessed."})
}

func projectEffectiveFirewalls(raw Object, network string) (Object, error) {
	return projectEffectiveFirewallScope(raw, network, false)
}
func projectEffectiveFirewallScope(raw Object, network string, regional bool) (Object, error) {
	out := Object{"network": "//compute.googleapis.com/" + network, "scope": "global_and_hierarchical_only", "effective_admission": "unknown", "complete": true}
	valid := true
	if regional {
		out["scope"] = "regional_global_and_hierarchical"
	}
	total := 0
	for _, field := range []string{"firewalls", "firewallPolicys"} {
		rows, e := viewerRows(raw, field)
		if e != nil {
			valid = false
			continue
		}
		if len(rows) > 10000 {
			valid = false
			rows = rows[:10000]
		}
		safeRows := []any{}
		for _, raw := range rows {
			d, ok := raw.(map[string]any)
			if !ok {
				valid = false
				safeRows = append(safeRows, Object{})
				continue
			}
			if field == "firewalls" {
				r, ok := projectEffectiveRule(d, false)
				if !ok {
					valid = false
				}
				name := Str(d["name"])
				if !backendID.MatchString(name) || len(name) > 63 || ingressNetwork(d["network"]) != network {
					valid = false
					r = Object{}
				} else {
					r["name"] = name
					r["network"] = "//compute.googleapis.com/" + network
				}
				safeRows = append(safeRows, r)
				total++
				continue
			}
			policy := Object{}
			switch d["type"] {
			case "HIERARCHY", "NETWORK", "SYSTEM", "UNSPECIFIED":
				policy["type"] = d["type"]
			case "NETWORK_REGIONAL", "SYSTEM_GLOBAL", "SYSTEM_REGIONAL":
				if regional {
					policy["type"] = d["type"]
				} else {
					valid = false
				}
			default:
				valid = false
			}
			if v, exists := d["priority"]; exists {
				if n, ok := effectiveFirewallInteger(v, 2147483647); ok {
					policy["priority"] = n
				} else {
					valid = false
				}
			}
			rules, e := viewerRows(d, "rules")
			if e != nil {
				valid = false
			}
			projected := []any{}
			for _, raw := range rules {
				total++
				if total > 10000 {
					valid = false
					break
				}
				r, ok := raw.(map[string]any)
				if !ok {
					valid = false
					projected = append(projected, Object{})
					continue
				}
				p, ok := projectEffectiveRule(r, true)
				if !ok {
					valid = false
				}
				projected = append(projected, p)
			}
			policy["rules"] = projected
			safeRows = append(safeRows, policy)
		}
		out[field] = safeRows
	}
	if !valid {
		out["complete"] = false
		return out, fmt.Errorf("some effective firewall metadata malformed or beyond projection bounds")
	}
	return out, nil
}
func effectiveFirewallInteger(v any, max int) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), n >= 0 && n <= float64(max) && float64(int(n)) == n
	case int:
		return n, n >= 0 && n <= max
	}
	return 0, false
}

func projectEffectiveRule(d Object, policy bool) (Object, bool) {
	out := Object{}
	valid := true
	maxPriority := 65535
	if policy {
		maxPriority = 2147483647
		for _, required := range []string{"priority", "direction", "match"} {
			if _, exists := d[required]; !exists {
				valid = false
			}
		}
	}
	if v, exists := d["priority"]; exists {
		if n, ok := effectiveFirewallInteger(v, maxPriority); ok {
			out["priority"] = n
		} else {
			valid = false
		}
	}
	for _, field := range []string{"disabled"} {
		if v, exists := d[field]; exists {
			if b, ok := v.(bool); ok {
				out[field] = b
			} else {
				valid = false
			}
		}
	}
	if v, exists := d["direction"]; exists {
		switch v {
		case "INGRESS", "EGRESS":
			out["direction"] = v
		default:
			valid = false
		}
	}
	if policy {
		switch d["action"] {
		case "allow", "deny", "goto_next", "apply_security_profile_group":
			out["action"] = d["action"]
		default:
			valid = false
		}
		if v, exists := d["targetType"]; exists {
			switch v {
			case "INSTANCES", "INTERNAL_MANAGED_LB":
				out["targetType"] = v
			default:
				valid = false
			}
		}
	}
	fields := []string{"sourceRanges", "destinationRanges", "sourceTags", "targetTags", "sourceServiceAccounts", "targetServiceAccounts"}
	if policy {
		fields = []string{"targetResources", "targetServiceAccounts"}
	}
	for _, field := range fields {
		if _, exists := d[field]; !exists {
			continue
		}
		rows, ok := ingressStrings(d, field)
		if !ok {
			valid = false
			continue
		}
		safe := []any{}
		for _, s := range rows {
			good := false
			switch field {
			case "sourceRanges", "destinationRanges":
				p, e := netip.ParsePrefix(s)
				good = e == nil && !p.Addr().Is4In6()
				if good {
					s = p.Masked().String()
				}
			case "sourceTags", "targetTags":
				good = ingressTag.MatchString(s)
			case "sourceServiceAccounts", "targetServiceAccounts":
				good = serviceAccountEmail.MatchString(s)
			case "targetResources":
				s = ingressNetwork(s)
				good = s != ""
			}
			if good {
				safe = append(safe, s)
			} else {
				valid = false
			}
		}
		out[field] = safe
	}
	if policy {
		if v, exists := d["targetSecureTags"]; exists {
			tags, ok := effectiveSecureTags(v)
			if !ok {
				valid = false
			}
			out["targetSecureTags"] = tags
		}
		if v, exists := d["match"]; exists {
			m, ok := v.(map[string]any)
			if !ok {
				valid = false
			} else {
				matcher, ok := projectEffectiveMatcher(m)
				out["match"] = matcher
				if !ok {
					valid = false
				}
			}
		}
	} else {
		for _, field := range []string{"allowed", "denied"} {
			if v, exists := d[field]; exists {
				rows, ok := effectiveLayer4(v, "IPProtocol")
				out[field] = rows
				if !ok {
					valid = false
				}
			}
		}
	}
	if !valid {
		out["projection_complete"] = false
	}
	return out, valid
}

func effectiveSecureTags(raw any) ([]any, bool) {
	rows, ok := raw.([]any)
	if !ok || len(rows) > 256 {
		return nil, false
	}
	out := []any{}
	valid := true
	re := regexp.MustCompile(`^tagValues/[0-9]+$`)
	for _, raw := range rows {
		d := Obj(raw)
		name := Str(d["name"])
		state := Str(d["state"])
		if !re.MatchString(name) || (state != "EFFECTIVE" && state != "INEFFECTIVE") {
			valid = false
			out = append(out, Object{})
			continue
		}
		out = append(out, Object{"name": name, "state": state})
	}
	return out, valid
}

func effectiveLayer4(raw any, key string) ([]any, bool) {
	rows, ok := raw.([]any)
	if !ok || len(rows) > 256 {
		return nil, false
	}
	out := []any{}
	valid := true
	for _, raw := range rows {
		d := Obj(raw)
		proto := Str(d[key])
		allowed := proto == "all"
		for _, p := range []string{"tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp"} {
			if proto == p {
				allowed = true
			}
		}
		if n, ok := viewerComputeUint64(proto); ok {
			v := 0
			for _, c := range n {
				v = v*10 + int(c-'0')
				if v > 255 {
					break
				}
			}
			allowed = v > 0 && v <= 255
		}
		ports, ok := ingressStrings(d, "ports")
		if !ok || !allowed {
			valid = false
			out = append(out, Object{})
			continue
		}
		safePorts := []any{}
		for _, port := range ports {
			parts := strings.Split(port, "-")
			good := len(parts) <= 2
			last := -1
			for _, p := range parts {
				n, ok := viewerComputeUint64(p)
				if !ok || len(n) > 5 {
					good = false
					break
				}
				value := 0
				for _, c := range n {
					value = value*10 + int(c-'0')
				}
				if value > 65535 || value < last {
					good = false
				}
				last = value
			}
			if proto != "tcp" && proto != "udp" && proto != "6" && proto != "17" {
				good = false
			}
			if good {
				safePorts = append(safePorts, port)
			} else {
				valid = false
			}
		}
		out = append(out, Object{key: proto, "ports": safePorts})
	}
	return out, valid
}

func projectEffectiveMatcher(m Object) (Object, bool) {
	out := Object{}
	valid := true
	for k, v := range m {
		switch k {
		case "srcIpRanges", "destIpRanges":
			rows, ok := ingressStrings(m, k)
			if !ok {
				valid = false
				continue
			}
			safe := []any{}
			for _, s := range rows {
				p, e := netip.ParsePrefix(s)
				if e != nil || p.Addr().Is4In6() {
					valid = false
				} else {
					safe = append(safe, p.Masked().String())
				}
			}
			out[k] = safe
		case "layer4Configs":
			rows, ok := effectiveLayer4(v, "ipProtocol")
			out[k] = rows
			if !ok {
				valid = false
			}
		case "srcSecureTags":
			rows, ok := effectiveSecureTags(v)
			out[k] = rows
			if !ok {
				valid = false
			}
		case "srcNetworkType", "destNetworkType", "srcNetworkContext", "destNetworkContext":
			switch v {
			case "INTERNET", "INTRA_VPC", "NON_INTERNET", "UNSPECIFIED", "VPC_NETWORKS":
				out[k] = v
			default:
				valid = false
			}
		case "srcFqdns", "destFqdns", "srcAddressGroups", "destAddressGroups", "srcRegionCodes", "destRegionCodes", "srcThreatIntelligences", "destThreatIntelligences", "srcNetworks":
			rows, ok := ingressStrings(m, k)
			if !ok {
				valid = false
			} else {
				out[k+"_count"] = len(rows)
			}
		default:
			valid = false
		}
	}
	return out, valid
}
