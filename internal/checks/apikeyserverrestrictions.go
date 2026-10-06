package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
)

// apiKeyUnrestrictedServerSources examines only explicit caller IP metadata.
// Presence of a client-restriction object is not proof of a restrictive range.
// Missing/invalid CIDRs and contradictory client unions stay unknown.
func apiKeyUnrestrictedServerSources(a inventory.Asset) []Result {
	if a.Type != "apikeys.googleapis.com/Key" || s(val(a, "deleteTime")) != "" {
		return nil
	}
	r := obj(val(a, "restrictions"))
	server := obj(r["serverKeyRestrictions"])
	if server == nil {
		return nil
	}
	for _, other := range []string{"browserKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions"} {
		if _, exists := r[other]; exists {
			return nil
		}
	}
	rows, ok := server["allowedIps"].([]any)
	if !ok || len(rows) == 0 || len(rows) > 4096 {
		return nil
	}
	ipv4, ipv6 := false, false
	for _, raw := range rows {
		text, ok := raw.(string)
		if !ok || len(text) > 128 {
			return nil
		}
		if address, err := netip.ParseAddr(text); err == nil {
			if address.Zone() != "" || address.Is4In6() {
				return nil
			}
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4In6() {
			return nil
		}
		if prefix.Bits() == 0 {
			if prefix.Addr().Is4() {
				ipv4 = true
			} else {
				ipv6 = true
			}
		}
	}
	if !ipv4 && !ipv6 {
		return nil
	}
	families := []any{}
	if ipv4 {
		families = append(families, "IPv4")
	}
	if ipv6 {
		families = append(families, "IPv6")
	}
	return result("medium", "API key server restriction explicitly allows an entire IP family", "Restrict caller IP ranges to intended clients and retain appropriate API restrictions and independent authorization controls.", inventory.Object{"restriction_type": "serverKeyRestrictions", "unrestricted_ip_families": families, "assessment": "Explicit /0 caller range in API-key metadata only; specific ranges alongside it do not narrow that address family's configured allowlist. The other address family is not inferred. Key validity/type, enabled APIs, API restrictions, IAM and application authorization remain independent. No key string was requested or tested and no private-data access is established."})
}
