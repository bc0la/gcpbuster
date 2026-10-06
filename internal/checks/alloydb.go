package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
	"sort"
	"time"
)

func alloyDBPublicConfiguration(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "alloydb.googleapis.com/Instance" {
		return nil
	}
	enabled, known := val(a, "networkConfig", "enablePublicIp").(bool)
	address, e := netip.ParseAddr(s(val(a, "publicIpAddress")))
	observed := e == nil && address.IsGlobalUnicast() && !address.IsPrivate() && !address.Is4In6() && address.Zone() == ""
	// A contradictory explicit disabled flag is unknown, not enabled.
	if known && !enabled {
		return nil
	}
	if !enabled && !observed {
		return nil
	}
	evidence := inventory.Object{"public_ip_enabled_observed": enabled, "public_ip_address_observed": observed, "assessment": "Public-IP configuration only. Authorized-network restrictions, connector IAM, SQL authentication, runtime state and reachability remain independent; no connection, SQL or endpoint probe occurred."}
	if value, ok := val(a, "clientConnectionConfig", "requireConnectors").(bool); ok {
		evidence["require_connectors"] = value
	}
	world := map[string]bool{}
	for _, raw := range arr(val(a, "networkConfig", "authorizedExternalNetworks")) {
		p, err := netip.ParsePrefix(s(obj(raw)["cidrRange"]))
		if err == nil && p.Bits() == 0 && !p.Addr().Is4In6() {
			world[p.Masked().String()] = true
		}
	}
	ranges := []string{}
	for p := range world {
		ranges = append(ranges, p)
	}
	sort.Strings(ranges)
	if len(ranges) > 0 {
		evidence["world_authorized_ranges"] = ranges
		return result("medium", "AlloyDB public-IP configuration includes world-source authorized networks", "Replace world-source ranges with necessary client ranges or require supported AlloyDB connectors; retain SQL authentication and verify intended access.", evidence)
	}
	return result("info", "AlloyDB instance configures public IP connectivity", "Verify public connectivity is intended; review authorized networks, connector enforcement and SQL authentication.", evidence)
}

func alloyDBClientProtection(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "alloydb.googleapis.com/Instance" {
		return nil
	}
	var out []Result
	require, known := val(a, "clientConnectionConfig", "requireConnectors").(bool)
	if known && !require {
		out = append(out, Result{"info", "AlloyDB connector-only enforcement is explicitly disabled", inventory.Object{"require_connectors": false, "assessment": "Direct-client configuration is permitted; this is not proof of unauthenticated SQL access or reachable networking. SQL authentication and separately configured TLS still apply."}, "Review whether policy requires AlloyDB Auth Proxy or language connectors, and enforce them where appropriate."})
	}
	mode := s(val(a, "clientConnectionConfig", "sslConfig", "sslMode"))
	if !(known && require) && (mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" || mode == "SSL_MODE_ALLOW") {
		out = append(out, Result{"medium", "AlloyDB direct-client TLS configuration permits unencrypted connections", inventory.Object{"ssl_mode": mode, "assessment": "Explicit optional-TLS configuration only. Connector use, client behavior, network reachability and actual traffic encryption are not measured; no SQL or client connection occurred."}, "Require encrypted direct-client connections or enforce AlloyDB connectors. Validate compatible clients before changing configuration."})
	}
	return out
}

func alloyDBDataAPI(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "alloydb.googleapis.com/Instance" || s(val(a, "dataApiAccess")) != "ENABLED" {
		return nil
	}
	return result("info", "AlloyDB Data API access is explicitly enabled", "Review whether Data API access is required and restrict the corresponding IAM and database authorization. Disable it if not intended.", inventory.Object{"data_api_access": "ENABLED", "assessment": "The configured Data API permits authorized users to use ExecuteSql through the public API, including for private-IP instances. This is not anonymous access or proof of SQL grants, database privileges or reachability. No SQL execution or connectivity test occurred."})
}
