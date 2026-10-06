package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var ingressContextNetwork = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/global/networks/[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var ingressContextVM = regexp.MustCompile(`^//compute\.googleapis\.com/projects/[A-Za-z0-9_-]+/zones/[a-z][a-z0-9-]*/instances/([a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$`)

func ingressContextInt(raw any, max int) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, v >= 0 && v <= max
	case float64:
		return int(v), v >= 0 && v <= float64(max) && float64(int(v)) == v
	}
	return 0, false
}
func ingressContextNormalizeNetwork(raw string) string {
	for _, p := range []string{"//compute.googleapis.com/", "https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		raw = strings.TrimPrefix(raw, p)
	}
	if !ingressContextNetwork.MatchString(raw) {
		return ""
	}
	return raw
}
func ingressContextNIC(a inventory.Asset, r inventory.Object) (inventory.Object, bool) {
	i, ok := ingressContextInt(r["interface_index"], 63)
	if !ok {
		return nil, false
	}
	nics := arr(val(a, "networkInterfaces"))
	if i >= len(nics) {
		return nil, false
	}
	nic := obj(nics[i])
	network := ingressContextNormalizeNetwork(s(nic["network"]))
	if network == "" || r["network"] != "//compute.googleapis.com/"+network {
		return nil, false
	}
	family, ok := ingressContextInt(r["external_address_family"], 6)
	if !ok || (family != 4 && family != 6) {
		return nil, false
	}
	field, key := "accessConfigs", "natIP"
	if family == 6 {
		field, key = "ipv6AccessConfigs", "externalIpv6"
	}
	found := false
	for _, raw := range arr(nic[field]) {
		ip, e := netip.ParseAddr(s(obj(raw)[key]))
		if e == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && ((family == 4 && ip.Is4()) || (family == 6 && ip.Is6() && !ip.Is4In6())) {
			found = true
		}
	}
	if !found {
		return nil, false
	}
	return inventory.Object{"interface_index": i, "network": r["network"], "external_address_family": family}, true
}
func ingressContextAllowed(raw any) ([]any, bool) {
	rows, ok := raw.([]any)
	if !ok || len(rows) == 0 || len(rows) > 256 {
		return nil, false
	}
	out := []any{}
	for _, raw := range rows {
		r := obj(raw)
		protocol := s(r["IPProtocol"])
		n, e := strconv.Atoi(protocol)
		numeric := e == nil && n > 0 && n <= 255 && strconv.Itoa(n) == protocol
		named := false
		for _, x := range []string{"all", "tcp", "udp", "icmp", "esp", "ah", "sctp", "ipip"} {
			if x == protocol {
				named = true
			}
		}
		if !numeric && !named {
			return nil, false
		}
		ports, ok := r["ports"].([]any)
		if !ok || len(ports) > 1024 {
			return nil, false
		}
		if len(ports) > 0 && protocol != "tcp" && protocol != "udp" && n != 6 && n != 17 {
			return nil, false
		}
		safe := []any{}
		for _, v := range ports {
			port, ok := v.(string)
			if !ok {
				return nil, false
			}
			p := strings.Split(port, "-")
			if len(p) > 2 {
				return nil, false
			}
			lo, e := strconv.ParseUint(p[0], 10, 16)
			if e != nil || strconv.FormatUint(lo, 10) != p[0] {
				return nil, false
			}
			if len(p) == 2 {
				hi, e := strconv.ParseUint(p[1], 10, 16)
				if e != nil || hi < lo || strconv.FormatUint(hi, 10) != p[1] {
					return nil, false
				}
			}
			safe = append(safe, port)
		}
		out = append(out, inventory.Object{"IPProtocol": protocol, "ports": safe})
	}
	return out, true
}

func computeIngressContextEvidence(a inventory.Asset) inventory.Object {
	empty := inventory.Object{"status": "unknown", "effective_admission": "unknown"}
	m := ingressContextVM.FindStringSubmatch(a.Name)
	if a.Type != "compute.googleapis.com/Instance" || m == nil || s(val(a, "name")) != m[1] {
		return empty
	}
	raw := obj(val(a, "_gcpbusterComputeIngressContext"))
	status := s(raw["status"])
	if (status != "configured_candidates" && status != "partial") || raw["effective_admission"] != "unknown" {
		return empty
	}
	out := inventory.Object{"status": status, "effective_admission": "unknown", "assessment": "Configured rule and default internet-gateway route candidates only; effective admission, route selection, runtime/listener state and reachability remain unverified."}
	matches := []any{}
	rows, ok := raw["matches"].([]any)
	if !ok || len(rows) > 512 {
		return empty
	}
	for _, v := range rows {
		r := obj(v)
		safe, ok := ingressContextNIC(a, r)
		if !ok {
			continue
		}
		network := strings.TrimPrefix(s(safe["network"]), "//compute.googleapis.com/")
		project := strings.Split(network, "/")[1]
		rule := s(r["firewall_resource"])
		if !regexp.MustCompile(`^//compute\.googleapis\.com/projects/` + regexp.QuoteMeta(project) + `/global/firewalls/[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`).MatchString(rule) {
			continue
		}
		priority, ok := ingressContextInt(r["priority"], 65535)
		if !ok {
			continue
		}
		target := s(r["target_match"])
		if target != "all_instances_in_network" && target != "target_tag" && target != "target_service_account" {
			continue
		}
		dest := s(r["destination_match"])
		if dest != "explicit_nic_address" && dest != "implicit_target_addresses" {
			continue
		}
		allowed, ok := ingressContextAllowed(r["allowed"])
		if !ok {
			continue
		}
		safe["firewall_resource"], safe["priority"], safe["target_match"], safe["destination_match"], safe["allowed"] = rule, priority, target, dest, allowed
		safe["classic_deny_context"] = classicDenyContextEvidence(r["classic_deny_context"], project, priority)
		nic := obj(arr(val(a, "networkInterfaces"))[safe["interface_index"].(int)])
		subnet := s(nic["subnetwork"])
		for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
			subnet = strings.TrimPrefix(subnet, prefix)
		}
		region := ""
		if parts := regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/regions/([a-z][a-z0-9-]*)/subnetworks/[a-z][-a-z0-9]*$`).FindStringSubmatch(subnet); parts != nil {
			region = parts[1]
		}
		safe["effective_policy_context"] = effectiveFirewallContextEvidence(r["effective_policy_context"], s(safe["network"]), region, strconv.Itoa(safe["external_address_family"].(int)))
		matches = append(matches, safe)
	}
	out["matches"] = matches
	routes := []any{}
	if rows, ok := raw["internet_gateway_routes"].([]any); ok && len(rows) <= 512 {
		for _, v := range rows {
			r := obj(v)
			safe, ok := ingressContextNIC(a, r)
			if !ok || r["next_hop"] != "default_internet_gateway" {
				continue
			}
			network := strings.TrimPrefix(s(safe["network"]), "//compute.googleapis.com/")
			project := strings.Split(network, "/")[1]
			resource := s(r["route_resource"])
			if !regexp.MustCompile(`^//compute\.googleapis\.com/projects/` + regexp.QuoteMeta(project) + `/global/routes/[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`).MatchString(resource) {
				continue
			}
			priority, ok := ingressContextInt(r["priority"], 65535)
			if !ok {
				continue
			}
			prefix := s(r["dest_range"])
			if (safe["external_address_family"] == 4 && prefix != "0.0.0.0/0") || (safe["external_address_family"] == 6 && prefix != "::/0") {
				continue
			}
			safe["route_resource"], safe["priority"], safe["dest_range"], safe["next_hop"] = resource, priority, prefix, "default_internet_gateway"
			routes = append(routes, safe)
		}
	}
	out["internet_gateway_routes"] = routes
	policyContexts := []any{}
	if rows, ok := raw["effective_policy_contexts"].([]any); ok && len(rows) <= 128 {
		for _, v := range rows {
			r := obj(v)
			safe, ok := ingressContextNIC(a, r)
			if !ok {
				continue
			}
			nic := obj(arr(val(a, "networkInterfaces"))[safe["interface_index"].(int)])
			subnet := s(nic["subnetwork"])
			for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
				subnet = strings.TrimPrefix(subnet, prefix)
			}
			region := ""
			if parts := regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/regions/([a-z][a-z0-9-]*)/subnetworks/[a-z][-a-z0-9]*$`).FindStringSubmatch(subnet); parts != nil {
				region = parts[1]
			}
			safe["context"] = effectiveFirewallContextEvidence(r["context"], s(safe["network"]), region, strconv.Itoa(safe["external_address_family"].(int)))
			policyContexts = append(policyContexts, safe)
		}
	}
	out["effective_policy_contexts"] = policyContexts
	return out
}
