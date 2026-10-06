package inventory

import (
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ingressInstanceName = regexp.MustCompile(`^//compute\.googleapis\.com/projects/([A-Za-z0-9_-]+)/zones/([a-z][a-z0-9-]*)/instances/([a-z][-a-z0-9]{0,62})$`)
var ingressFirewallName = regexp.MustCompile(`^//compute\.googleapis\.com/projects/([A-Za-z0-9_-]+)/global/firewalls/([a-z][-a-z0-9]{0,62})$`)
var ingressTag = regexp.MustCompile(`^[a-z][-a-z0-9]{0,62}$`)

func ingressNetwork(raw any) string {
	s, ok := raw.(string)
	if !ok || !viewerNetworkReference.MatchString(s) {
		return ""
	}
	for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}
func ingressStrings(d Object, key string) ([]string, bool) {
	v, exists := d[key]
	if !exists {
		return nil, true
	}
	rows, ok := v.([]any)
	if !ok || len(rows) > 1024 {
		return nil, false
	}
	out := []string{}
	for _, v := range rows {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

type ingressCandidate struct {
	asset          Asset
	network        string
	family         int
	tags, accounts []string
	dest           []netip.Prefix
	allowed        []any
	priority       int
}

func parseIngressCandidate(a Asset) (ingressCandidate, bool) {
	c := ingressCandidate{asset: a, priority: 1000}
	m := ingressFirewallName.FindStringSubmatch(a.Name)
	d := a.Resource.Data
	if a.Type != "compute.googleapis.com/Firewall" || m == nil || Str(d["name"]) != m[2] {
		return c, false
	}
	c.network = ingressNetwork(d["network"])
	if c.network == "" || !strings.HasPrefix(c.network, "projects/"+m[1]+"/") {
		return c, false
	}
	if v, exists := d["disabled"]; exists {
		if b, ok := v.(bool); !ok || b {
			return c, false
		}
	}
	if v, exists := d["direction"]; exists {
		if v != "INGRESS" {
			return c, false
		}
	}
	if v, exists := d["priority"]; exists {
		n, ok := v.(float64)
		if !ok || n < 0 || n > 65535 || float64(int(n)) != n {
			return c, false
		}
		c.priority = int(n)
	}
	if v, exists := d["denied"]; exists {
		rows, ok := v.([]any)
		if !ok || len(rows) > 0 {
			return c, false
		}
	}
	fields := map[string][]string{}
	for _, k := range []string{"sourceRanges", "sourceTags", "sourceServiceAccounts", "targetTags", "targetServiceAccounts", "destinationRanges"} {
		rows, ok := ingressStrings(d, k)
		if !ok {
			return c, false
		}
		fields[k] = rows
	}
	if len(fields["sourceTags"])+len(fields["targetTags"]) > 0 && len(fields["sourceServiceAccounts"])+len(fields["targetServiceAccounts"]) > 0 {
		return c, false
	}
	for _, key := range []string{"sourceTags", "targetTags"} {
		for _, s := range fields[key] {
			if !ingressTag.MatchString(s) {
				return c, false
			}
		}
	}
	for _, key := range []string{"sourceServiceAccounts", "targetServiceAccounts"} {
		for _, s := range fields[key] {
			if !serviceAccountEmail.MatchString(s) {
				return c, false
			}
		}
	}
	world := false
	for _, key := range []string{"sourceRanges", "destinationRanges"} {
		for _, s := range fields[key] {
			p, e := netip.ParsePrefix(s)
			if e != nil || p.Addr().Is4In6() {
				return c, false
			}
			family := 6
			if p.Addr().Is4() {
				family = 4
			}
			if c.family != 0 && c.family != family {
				return c, false
			}
			c.family = family
			if key == "sourceRanges" && p.Bits() == 0 {
				world = true
			}
			if key == "destinationRanges" {
				c.dest = append(c.dest, p.Masked())
			}
		}
	}
	if len(fields["sourceRanges"])+len(fields["sourceTags"])+len(fields["sourceServiceAccounts"]) == 0 {
		if c.family == 6 {
			return c, false
		}
		c.family = 4
		world = true
	}
	if !world {
		return c, false
	}
	c.tags, c.accounts = fields["targetTags"], fields["targetServiceAccounts"]
	rows, ok := d["allowed"].([]any)
	if !ok || len(rows) == 0 || len(rows) > 256 {
		return c, false
	}
	for _, raw := range rows {
		r, ok := raw.(map[string]any)
		if !ok {
			return c, false
		}
		proto := Str(r["IPProtocol"])
		n, err := strconv.Atoi(proto)
		numeric := err == nil && n > 0 && n <= 255 && strconv.Itoa(n) == proto
		named := proto == "all" || proto == "tcp" || proto == "udp" || proto == "icmp" || proto == "esp" || proto == "ah" || proto == "ipip" || proto == "sctp"
		if !numeric && !named {
			return c, false
		}
		ports, ok := ingressStrings(r, "ports")
		if !ok {
			return c, false
		}
		if len(ports) > 0 && proto != "tcp" && proto != "udp" && n != 6 && n != 17 {
			return c, false
		}
		clean := []any{}
		for _, port := range ports {
			p := strings.Split(port, "-")
			if len(p) > 2 {
				return c, false
			}
			lo, e := strconv.ParseUint(p[0], 10, 16)
			if e != nil || strconv.FormatUint(lo, 10) != p[0] {
				return c, false
			}
			if len(p) == 2 {
				hi, e := strconv.ParseUint(p[1], 10, 16)
				if e != nil || hi < lo || strconv.FormatUint(hi, 10) != p[1] {
					return c, false
				}
			}
			clean = append(clean, port)
		}
		c.allowed = append(c.allowed, Object{"IPProtocol": proto, "ports": clean})
	}
	return c, true
}

// CorrelateComputeIngressContext joins configured candidates, NOT effective
// admission. VPC/hierarchical policy priority, routes and listeners stay unknown.
func CorrelateComputeIngressContext(snap *Snapshot) {
	routes, routePartial := computeInternetRouteCandidates(snap)
	effectiveContexts := effectiveNetworkFirewallContexts(snap)
	candidates := map[string][]ingressCandidate{}
	seen := map[string]Asset{}
	ambiguous := map[string]bool{}
	limited := false
	for _, a := range snap.Assets {
		if a.Type != "compute.googleapis.com/Firewall" {
			continue
		}
		if old, exists := seen[a.Name]; exists {
			if !reflect.DeepEqual(old.Resource.Data, a.Resource.Data) {
				ambiguous[a.Name] = true
				limited = true
			}
			continue
		}
		if len(seen) >= 10000 {
			limited = true
			continue
		}
		seen[a.Name] = a
	}
	keys := []string{}
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	denies, denyUnknown := observedClassicDenies(seen, ambiguous)
	for _, key := range keys {
		a := seen[key]
		if c, ok := parseIngressCandidate(a); ok {
			candidates[c.network] = append(candidates[c.network], c)
		}
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != "compute.googleapis.com/Instance" {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterComputeIngressContext")
		m := ingressInstanceName.FindStringSubmatch(a.Name)
		if m == nil || Str(a.Resource.Data["name"]) != m[3] {
			continue
		}
		matches := []any{}
		partial := limited || routePartial
		routeMatches := []any{}
		policyContexts := []any{}
		interfaces, ok := a.Resource.Data["networkInterfaces"].([]any)
		if !ok || len(interfaces) > 64 {
			a.Resource.Data["_gcpbusterComputeIngressContext"] = Object{"status": "unknown", "effective_admission": "unknown", "matches": matches}
			continue
		}
		tags, tagsOK := ingressStrings(Obj(a.Resource.Data["tags"]), "items")
		accounts := []string{}
		accountsOK := true
		if raw, exists := a.Resource.Data["serviceAccounts"]; exists {
			rows, ok := raw.([]any)
			if !ok || len(rows) > 100 {
				accountsOK = false
			} else {
				for _, r := range rows {
					s := Str(Obj(r)["email"])
					if !serviceAccountEmail.MatchString(s) {
						accountsOK = false
					} else {
						accounts = append(accounts, s)
					}
				}
			}
		}
		checks := 0
		for ni, raw := range interfaces {
			nic := Obj(raw)
			network := ingressNetwork(nic["network"])
			if network == "" {
				partial = true
				continue
			}
			families := map[int]bool{}
			for _, field := range []string{"accessConfigs", "ipv6AccessConfigs"} {
				if raw, exists := nic[field]; exists {
					rows, ok := raw.([]any)
					if !ok || len(rows) > 32 {
						partial = true
						continue
					}
					for _, raw := range rows {
						config := Obj(raw)
						key, family := "natIP", 4
						if field == "ipv6AccessConfigs" {
							key, family = "externalIpv6", 6
						}
						ip, e := netip.ParseAddr(Str(config[key]))
						if e == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && ((family == 4 && ip.Is4()) || (family == 6 && ip.Is6() && !ip.Is4In6())) {
							families[family] = true
						}
					}
				}
			}
			policyContext := effectiveContexts[network]
			if region := computeNICRegion(nic); region != "" {
				if regional := effectiveContexts[network+"|"+region]; regional != nil {
					policyContext = regional
				}
			}
			if policyContext != nil {
				for _, family := range []int{4, 6} {
					if families[family] {
						policyContexts = append(policyContexts, Object{"interface_index": ni, "network": "//compute.googleapis.com/" + network, "external_address_family": family, "context": policyContext})
					}
				}
			}
			for _, route := range routes[network] {
				family := route.family
				if !families[family] {
					continue
				}
				if len(route.tags) > 0 {
					if !tagsOK {
						partial = true
						continue
					}
					if !ingressOverlap(route.tags, tags) {
						continue
					}
				}
				if len(routeMatches) >= 512 {
					partial = true
					break
				}
				routeMatches = append(routeMatches, Object{"route_resource": route.name, "interface_index": ni, "network": "//compute.googleapis.com/" + network, "external_address_family": family, "priority": route.priority, "dest_range": route.prefix, "next_hop": "default_internet_gateway", "assessment": "configured_route_candidate_only"})
			}
			for _, c := range candidates[network] {
				checks++
				if checks > 20000 || len(matches) >= 512 {
					partial = true
					break
				}
				if ambiguous[c.asset.Name] {
					partial = true
					continue
				}
				if !families[c.family] {
					continue
				}
				target := "all_instances_in_network"
				if len(c.tags) > 0 {
					if !tagsOK {
						partial = true
						continue
					}
					if !ingressOverlap(c.tags, tags) {
						continue
					}
					target = "target_tag"
				}
				if len(c.accounts) > 0 {
					if !accountsOK {
						partial = true
						continue
					}
					if !ingressOverlap(c.accounts, accounts) {
						continue
					}
					target = "target_service_account"
				}
				if len(c.dest) > 0 {
					field := "networkIP"
					if c.family == 6 {
						field = "ipv6Address"
					}
					ip, e := netip.ParseAddr(Str(nic[field]))
					if e != nil {
						partial = true
						continue
					}
					contained := false
					for _, p := range c.dest {
						if p.Contains(ip) {
							contained = true
						}
					}
					if !contained {
						continue
					}
				}
				project := strings.Split(network, "/")[1]
				denyContext := classicDenyContext(c, denies[network], nic, tags, accounts, tagsOK, accountsOK, classicFirewallCoverage(snap, project, partial || denyUnknown[network] || denyUnknown[""]))
				effectiveContext := effectiveContexts[network]
				if region := computeNICRegion(nic); region != "" {
					if regional := effectiveContexts[network+"|"+region]; regional != nil {
						effectiveContext = regional
					}
				}
				if effectiveContext == nil {
					effectiveContext = Object{"network": "//compute.googleapis.com/" + network, "status": "unknown", "scope": "global_and_hierarchical_only", "regional_policy_coverage": "not_collected", "effective_admission": "unknown"}
				}
				matches = append(matches, Object{"firewall_resource": c.asset.Name, "effective_policy_context": effectiveContext, "classic_deny_context": denyContext, "interface_index": ni, "network": "//compute.googleapis.com/" + network, "external_address_family": c.family, "target_match": target, "priority": c.priority, "allowed": c.allowed, "destination_match": func() string {
					if len(c.dest) > 0 {
						return "explicit_nic_address"
					}
					return "implicit_target_addresses"
				}()})
			}
		}
		status := "configured_candidates"
		if partial {
			status = "partial"
		}
		a.Resource.Data["_gcpbusterComputeIngressContext"] = Object{"status": status, "effective_admission": "unknown", "matches": matches, "effective_policy_contexts": policyContexts, "internet_gateway_routes": routeMatches, "assessment": "Configured world-source allowance, NIC network, target selector, observed policy rule and default internet-gateway route candidates only. Effective policy ordering and admission, route selection, listening services, runtime state and actual reachability are not evaluated. Empty candidates do not establish blocked ingress."}
	}
}

type computeInternetRoute struct {
	name, prefix     string
	family, priority int
	tags             []string
}

func computeInternetRouteCandidates(snap *Snapshot) (map[string][]computeInternetRoute, bool) {
	out := map[string][]computeInternetRoute{}
	seen := map[string]Asset{}
	bad := map[string]bool{}
	partial := false
	for _, a := range snap.Assets {
		if a.Type != "compute.googleapis.com/Route" {
			continue
		}
		if v, exists := a.Resource.Data["projection_complete"]; exists && v != true {
			partial = true
			continue
		}
		if old, exists := seen[a.Name]; exists {
			if !reflect.DeepEqual(old.Resource.Data, a.Resource.Data) {
				bad[a.Name] = true
				partial = true
			}
			continue
		}
		if len(seen) >= 10000 {
			partial = true
			continue
		}
		seen[a.Name] = a
	}
	keys := []string{}
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	re := regexp.MustCompile(`^//compute\.googleapis\.com/projects/([A-Za-z0-9_-]+)/global/routes/([a-z](?:[-a-z0-9]*[a-z0-9])?)$`)
	for _, key := range keys {
		if bad[key] {
			continue
		}
		a := seen[key]
		d := a.Resource.Data
		conflictingHop := false
		for _, field := range []string{"nextHopInstance", "nextHopIp", "nextHopNetwork", "nextHopIlb", "nextHopPeering", "nextHopHub"} {
			if _, exists := d[field]; exists {
				conflictingHop = true
			}
		}
		if conflictingHop {
			partial = true
			continue
		}
		m := re.FindStringSubmatch(a.Name)
		if m == nil || len(m[2]) > 63 || Str(d["name"]) != m[2] {
			continue
		}
		network := ingressNetwork(d["network"])
		if !strings.HasPrefix(network, "projects/"+m[1]+"/") {
			continue
		}
		gateway := Str(d["nextHopGateway"])
		for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
			gateway = strings.TrimPrefix(gateway, prefix)
		}
		if gateway != "projects/"+m[1]+"/global/gateways/default-internet-gateway" {
			continue
		}
		p, e := netip.ParsePrefix(Str(d["destRange"]))
		if e != nil || p.Bits() != 0 || p.Addr().Is4In6() {
			continue
		}
		family := 6
		if p.Addr().Is4() {
			family = 4
		}
		priority := 1000
		if v, exists := d["priority"]; exists {
			n, ok := v.(float64)
			if !ok || n < 0 || n > 65535 || float64(int(n)) != n {
				continue
			}
			priority = int(n)
		}
		tags, ok := ingressStrings(d, "tags")
		if !ok {
			continue
		}
		valid := true
		for _, tag := range tags {
			if !ingressTag.MatchString(tag) {
				valid = false
			}
		}
		if !valid {
			continue
		}
		out[network] = append(out[network], computeInternetRoute{a.Name, p.Masked().String(), family, priority, tags})
	}
	return out, partial
}
func ingressOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
