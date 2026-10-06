package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var dnsNetworkName = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9._:-]*/global/networks/[a-z][a-z0-9-]{0,62}$`)
var dnsForwardDomain = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

func dnsNetworkReference(v any) string {
	value, ok := v.(string)
	if !ok {
		return ""
	}
	for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/", "//compute.googleapis.com/"} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimPrefix(value, prefix)
			break
		}
	}
	if !dnsNetworkName.MatchString(value) {
		return ""
	}
	return value
}
func dnsBoundNetworks(v any) []any {
	rows, ok := v.([]any)
	if !ok || len(rows) == 0 {
		return nil
	}
	seen := map[string]bool{}
	names := []string{}
	for _, r := range rows {
		name := dnsNetworkReference(obj(r)["networkUrl"])
		if name == "" {
			return nil
		}
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	sort.Strings(names)
	out := []any{}
	for _, n := range names {
		out = append(out, n)
	}
	return out
}
func dnsForwardTargets(v any, allowDomain bool) []any {
	rows, ok := v.([]any)
	if !ok || len(rows) == 0 {
		return nil
	}
	out := []any{}
	for _, r := range rows {
		d := obj(r)
		chosen := ""
		endpoint := ""
		for _, key := range []string{"ipv4Address", "ipv6Address", "domainName"} {
			if raw, exists := d[key]; exists {
				value, ok := raw.(string)
				if !ok || value == "" || chosen != "" {
					return nil
				}
				chosen = key
				endpoint = value
			}
		}
		switch chosen {
		case "ipv4Address", "ipv6Address":
			ip, e := netip.ParseAddr(endpoint)
			if e != nil || ip.Zone() != "" || ip.Is4In6() || (chosen == "ipv4Address") != ip.Is4() {
				return nil
			}
			endpoint = ip.String()
		case "domainName":
			if !allowDomain || len(endpoint) > 253 || !dnsForwardDomain.MatchString(endpoint) {
				return nil
			}
			endpoint = strings.ToLower(endpoint)
		default:
			return nil
		}
		path := "default"
		if raw, exists := d["forwardingPath"]; exists {
			var ok bool
			path, ok = raw.(string)
			if !ok || (path != "default" && path != "private") {
				return nil
			}
		}
		out = append(out, inventory.Object{"target_kind": chosen, "target": endpoint, "forwarding_path": path})
	}
	return out
}

func dnsPolicyForwarding(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "dns.googleapis.com/Policy" {
		return nil
	}
	networks := dnsBoundNetworks(val(a, "networks"))
	if len(networks) == 0 {
		return nil
	}
	var out []Result
	if enabled, ok := val(a, "enableInboundForwarding").(bool); ok && enabled {
		out = append(out, Result{"info", "Cloud DNS policy enables inbound forwarding", inventory.Object{"networks": networks, "inbound_forwarding": true, "assessment": "Configured inbound DNS forwarding on bound VPC networks. This does not establish internet exposure, connectivity, successful resolution or authorization; no DNS requests were sent."}, "Verify the intended hybrid DNS consumers and routing controls for the bound networks."})
	}
	targets := dnsForwardTargets(val(a, "alternativeNameServerConfig", "targetNameServers"), false)
	if len(targets) > 0 {
		out = append(out, Result{"info", "Cloud DNS policy configures alternative outbound resolvers", inventory.Object{"networks": networks, "targets": targets, "assessment": "VPC server-policy resolver configuration only. Cluster-scoped GKE DNS resources can take precedence; target ownership, routing, successful resolution and interception are unverified. No DNS requests were sent."}, "Confirm alternative resolvers are trusted and intended for these networks; review precedence and routing without assuming effective redirection."})
	}
	return out
}

func dnsZoneResolution(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "dns.googleapis.com/ManagedZone" || s(val(a, "visibility")) != "private" {
		return nil
	}
	networks := dnsBoundNetworks(val(a, "privateVisibilityConfig", "networks"))
	if len(networks) == 0 {
		return nil
	}
	_, hasForward := a.Resource.Data["forwardingConfig"]
	_, hasPeer := a.Resource.Data["peeringConfig"]
	if hasForward && hasPeer {
		return nil
	}
	targets := dnsForwardTargets(val(a, "forwardingConfig", "targetNameServers"), true)
	if len(targets) > 0 {
		return result("info", "Private Cloud DNS zone configures forwarding targets", "Confirm the suffix-scoped resolvers, consumer networks and forwarding path are intended and trusted.", inventory.Object{"networks": networks, "targets": targets, "assessment": "Private zone suffix forwarding configuration only. Higher-precedence policies, target ownership, routing and successful resolution remain unverified; no DNS requests or endpoint probes occurred."})
	}
	target := dnsNetworkReference(val(a, "peeringConfig", "targetNetwork", "networkUrl"))
	if target != "" {
		return result("info", "Private Cloud DNS zone configures DNS peering", "Review whether these consumer networks should use the target VPC's DNS view.", inventory.Object{"networks": networks, "target_network": target, "assessment": "DNS resolution-view peering only; it creates no packet-level VPC connectivity. Effective lookup results, namespace access and reachability are unverified; no DNS requests occurred."})
	}
	return nil
}

func dnsQueryLogging(a inventory.Asset, _ time.Time) []Result {
	scope := ""
	evidence := inventory.Object{}
	switch a.Type {
	case "dns.googleapis.com/Policy":
		if !isFalse(val(a, "enableLogging")) {
			return nil
		}
		networks := dnsBoundNetworks(val(a, "networks"))
		if len(networks) == 0 {
			return nil
		}
		evidence["networks"] = networks
		scope = "bound_vpc_networks"
	case "dns.googleapis.com/ManagedZone":
		if s(val(a, "visibility")) != "public" || !isFalse(val(a, "cloudLoggingConfig", "enableLogging")) {
			return nil
		}
		scope = "public_zone"
	default:
		return nil
	}
	evidence["scope"] = scope
	evidence["query_logging_enabled"] = false
	evidence["assessment"] = "Explicit product query-log configuration only, distinct from Cloud Audit Logs. Existing retained logs are not deleted; other logging sources and effective query activity were not examined."
	return result("low", "Cloud DNS query logging is explicitly disabled", "Enable applicable DNS query logging where required, accounting for retention, cost and sensitive queried-name data.", evidence)
}
