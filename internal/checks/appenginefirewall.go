package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"math"
	"net/netip"
	"sort"
	"time"
)

type appEngineRule struct {
	priority int
	action   string
	prefixes []netip.Prefix
}

// App Engine uses first-match, ascending numeric priority. Only complete,
// explicitly represented policies are assessed, without probing any endpoint.
func appEngineFirewall(a inventory.Asset, _ time.Time) []Result {
	complete, known := a.Resource.Data["complete"].(bool)
	if a.Type != "gcpbuster.googleapis.com/AppEngineFirewall" || !known || !complete {
		return nil
	}
	raw, ok := a.Resource.Data["rules"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 10000 {
		return nil
	}
	rules := []appEngineRule{}
	seen := map[int]bool{}
	hasDefault := false
	for _, v := range raw {
		d := obj(v)
		priority := 0
		switch n := d["priority"].(type) {
		case int:
			priority = n
		case float64:
			if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < 1 || n > 2147483647 {
				return nil
			}
			priority = int(n)
		default:
			return nil
		}
		if priority < 1 || priority > 2147483647 || seen[priority] {
			return nil
		}
		seen[priority] = true
		action := s(d["action"])
		if action != "ALLOW" && action != "DENY" {
			return nil
		}
		source := s(d["sourceRange"])
		if source == "0/0" {
			source = "0.0.0.0/0"
		}
		prefixes := []netip.Prefix{}
		if source == "*" {
			prefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		} else {
			p, err := netip.ParsePrefix(source)
			if err != nil {
				addr, e := netip.ParseAddr(source)
				if e != nil || addr.Zone() != "" || addr.Is4In6() {
					return nil
				}
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			if p.Addr().Is4In6() {
				return nil
			}
			prefixes = append(prefixes, p.Masked())
		}
		if priority == 2147483647 {
			if source != "*" {
				return nil
			}
			hasDefault = true
		}
		rules = append(rules, appEngineRule{priority, action, prefixes})
	}
	if !hasDefault {
		return nil
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].priority < rules[j].priority })
	covered := map[int][]netip.Prefix{}
	denied := map[int]bool{}
	emittedAll := map[int]bool{}
	var out []Result
	for _, rule := range rules {
		for _, p := range rule.prefixes {
			family := p.Addr().BitLen()
			prior := covered[family]
			unmatched := !appEnginePrefixCovered(p, prior)
			if rule.action == "DENY" && unmatched {
				denied[family] = true
			}
			if rule.action == "ALLOW" && p.Bits() == 0 && unmatched {
				scope := "unmatched_source_fallback"
				if !denied[family] {
					scope = "all_sources_in_family"
					emittedAll[family] = true
				}
				ipFamily := "IPv6"
				if family == 32 {
					ipFamily = "IPv4"
				}
				out = append(out, Result{"info", "App Engine firewall has broadly permissive source configuration", inventory.Object{"priority": rule.priority, "ip_family": ipFamily, "source_range": p.String(), "configured_scope": scope, "assessment": "First-match firewall configuration only; earlier matching rules take precedence. IAP, ingress, application authentication, serving state and firewall bypass behavior remain unverified. No effective reachability or endpoint access is established."}, "Review intended public access and first-match source restrictions together with ingress and application authentication. Do not infer effective reachability from this firewall configuration alone."})
			}
			covered[family] = append(prior, p)
		}
	}
	for _, family := range []int{32, 128} {
		world := netip.MustParsePrefix("::/0")
		ipFamily := "IPv6"
		if family == 32 {
			world = netip.MustParsePrefix("0.0.0.0/0")
			ipFamily = "IPv4"
		}
		if !emittedAll[family] && !denied[family] && appEnginePrefixCovered(world, covered[family]) {
			out = append(out, Result{"info", "App Engine firewall has broadly permissive source configuration", inventory.Object{"ip_family": ipFamily, "source_range": world.String(), "configured_scope": "all_sources_in_family", "basis": "union_of_first_match_allow_rules", "assessment": "Complete first-match policy permits every source address in this family through its combined ALLOW ranges. IAP, ingress, application authentication, serving state and firewall bypass behavior remain unverified. No effective reachability or endpoint access is established."}, "Review intended public access and combined source allowances together with ingress and application authentication."})
		}
	}
	return out
}

// Coverage is a prefix-union question: two /1 rules can entirely shadow /0.
func appEnginePrefixCovered(target netip.Prefix, prior []netip.Prefix) bool {
	overlaps := []netip.Prefix{}
	for _, p := range prior {
		if p.Addr().BitLen() != target.Addr().BitLen() {
			continue
		}
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
		if target.Contains(p.Addr()) {
			overlaps = append(overlaps, p)
		}
	}
	if len(overlaps) == 0 || target.Bits() == target.Addr().BitLen() {
		return false
	}
	bits := target.Bits()
	left := netip.PrefixFrom(target.Addr(), bits+1)
	var right netip.Prefix
	if target.Addr().Is4() {
		b := target.Addr().As4()
		b[bits/8] |= 1 << uint(7-bits%8)
		right = netip.PrefixFrom(netip.AddrFrom4(b), bits+1)
	} else {
		b := target.Addr().As16()
		b[bits/8] |= 1 << uint(7-bits%8)
		right = netip.PrefixFrom(netip.AddrFrom16(b), bits+1)
	}
	return appEnginePrefixCovered(left, overlaps) && appEnginePrefixCovered(right, overlaps)
}
