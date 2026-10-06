package inventory

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func observedClassicDenies(seen map[string]Asset, conflicts map[string]bool) (map[string][]ingressCandidate, map[string]bool) {
	out := map[string][]ingressCandidate{}
	unknown := map[string]bool{}
	keys := []string{}
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if conflicts[k] {
			unknown[ingressNetwork(seen[k].Resource.Data["network"])] = true
			continue
		}
		a := seen[k]
		d := a.Resource.Data
		network := ingressNetwork(d["network"])
		if disabled, ok := d["disabled"].(bool); ok && disabled {
			continue
		}
		if direction, ok := d["direction"].(string); ok && direction == "EGRESS" {
			continue
		}
		denied, ok := d["denied"].([]any)
		if !ok || len(denied) == 0 {
			if _, valid := parseIngressCandidate(a); !valid {
				unknown[network] = true
			}
			continue
		}
		if raw, exists := d["allowed"]; exists {
			rows, ok := raw.([]any)
			if !ok || len(rows) > 0 {
				unknown[network] = true
				continue
			}
		}
		clone := Object{}
		for k, v := range d {
			clone[k] = v
		}
		delete(clone, "denied")
		clone["allowed"] = denied
		a.Resource.Data = clone
		if c, ok := parseIngressCandidate(a); ok {
			out[c.network] = append(out[c.network], c)
		} else {
			unknown[network] = true
		}
	}
	return out, unknown
}

func classicFirewallCoverage(snap *Snapshot, project string, partial bool) bool {
	if partial {
		return false
	}
	found := false
	for _, c := range snap.Coverage {
		if c.Source != "viewer-compute-firewalls:"+project {
			continue
		}
		if c.Status != "completed" {
			return false
		}
		found = true
	}
	return found
}

type classicPortInterval struct{ lo, hi int }

func classicProtocol(s string) string {
	switch s {
	case "tcp":
		return "6"
	case "udp":
		return "17"
	case "icmp":
		return "1"
	case "esp":
		return "50"
	case "ah":
		return "51"
	case "sctp":
		return "132"
	case "ipip":
		return "4"
	}
	return s
}
func classicPorts(r Object) []classicPortInterval {
	rows := List(r["ports"])
	if len(rows) == 0 {
		return []classicPortInterval{{0, 65535}}
	}
	out := []classicPortInterval{}
	for _, v := range rows {
		p := strings.Split(Str(v), "-")
		lo, _ := strconv.Atoi(p[0])
		hi := lo
		if len(p) == 2 {
			hi, _ = strconv.Atoi(p[1])
		}
		out = append(out, classicPortInterval{lo, hi})
	}
	return out
}
func classicProtocolPortRelation(allow, deny []any) (overlap, covered bool) {
	covered = true
	for _, raw := range allow {
		a := Obj(raw)
		protocol := classicProtocol(Str(a["IPProtocol"]))
		intervals := []classicPortInterval{}
		for _, raw := range deny {
			d := Obj(raw)
			dp := classicProtocol(Str(d["IPProtocol"]))
			if dp == "all" || dp == protocol {
				intervals = append(intervals, classicPorts(d)...)
			} else if protocol == "all" {
				overlap = true
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].lo < intervals[j].lo })
		for _, wanted := range classicPorts(a) {
			cursor := wanted.lo
			for _, candidate := range intervals {
				if candidate.lo <= wanted.hi && candidate.hi >= wanted.lo {
					overlap = true
				}
				if candidate.lo <= cursor && candidate.hi >= cursor {
					cursor = candidate.hi + 1
				}
			}
			if cursor <= wanted.hi {
				covered = false
			}
		}
	}
	return
}

func classicDenyContext(c ingressCandidate, denies []ingressCandidate, nic Object, tags, accounts []string, tagsOK, accountsOK, complete bool) Object {
	out := Object{"status": "unknown", "snapshot_coverage": "unknown", "effective_admission": "unknown", "denies": []any{}}
	if complete {
		out["snapshot_coverage"] = "completed"
	}
	merged := []any{}
	observed := []any{}
	units := 0
	for _, raw := range c.allowed {
		units += 1 + len(List(Obj(raw)["ports"]))
	}
	if units > 256 {
		return out
	}
	checked := 0
	for _, d := range denies {
		checked++
		if checked > 256 {
			out["snapshot_coverage"] = "unknown"
			complete = false
			break
		}
		if d.family != c.family || d.priority > c.priority {
			continue
		}
		if len(d.tags) > 0 && (!tagsOK || !ingressOverlap(d.tags, tags)) {
			continue
		}
		if len(d.accounts) > 0 && (!accountsOK || !ingressOverlap(d.accounts, accounts)) {
			continue
		}
		// Require deny destinations to cover the entire configured allow destination
		// set. Omitted deny destinations cover target addresses, but an explicitly
		// narrowed deny cannot prove complete coverage of an implicit allow set.
		destinationsCovered := len(d.dest) == 0
		destinationsOverlap := destinationsCovered
		if len(d.dest) > 0 {
			field := "networkIP"
			if c.family == 6 {
				field = "ipv6Address"
			}
			ip, e := netip.ParseAddr(Str(nic[field]))
			if e != nil {
				continue
			}
			for _, p := range d.dest {
				if p.Contains(ip) {
					destinationsOverlap = true
				}
			}
			if len(c.dest) > 0 {
				destinationsCovered = true
				for _, wanted := range c.dest {
					covered := false
					for _, p := range d.dest {
						if p.Bits() <= wanted.Bits() && p.Contains(wanted.Addr()) {
							covered = true
						}
					}
					if !covered {
						destinationsCovered = false
					}
				}
			}
		}
		if !destinationsOverlap {
			continue
		}
		for _, raw := range d.allowed {
			units += 1 + len(List(Obj(raw)["ports"]))
		}
		if units > 256 {
			out["snapshot_coverage"] = "unknown"
			complete = false
			break
		}
		overlap, _ := classicProtocolPortRelation(c.allowed, d.allowed)
		if !overlap {
			continue
		}
		if len(observed) >= 256 {
			complete = false
			out["snapshot_coverage"] = "unknown"
			break
		}
		observed = append(observed, Object{"firewall_resource": d.asset.Name, "priority": d.priority})
		if destinationsCovered {
			merged = append(merged, d.allowed...)
		}
	}
	out["denies"] = observed
	if len(observed) > 0 {
		out["status"] = "observed_overlap"
	}
	_, covered := classicProtocolPortRelation(c.allowed, merged)
	if complete && covered {
		out["status"] = "definitely_shadowed_by_observed_classic_deny"
	}
	return out
}
