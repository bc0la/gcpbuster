package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var peeringName = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
var peerNetworkRef = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9._:-]*/global/networks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Review configured exchange flags only. ACTIVE is not proof that the peer has
// consented to custom route exchange, that routes exist, or that traffic passes.
// https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks
func networkPeeringRoutes(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "compute.googleapis.com/Network" {
		return nil
	}
	var out []Result
	for _, raw := range arr(val(a, "peerings")) {
		p := obj(raw)
		name := s(p["name"])
		if !peeringName.MatchString(name) || s(p["state"]) != "ACTIVE" {
			continue
		}
		ref := s(p["network"])
		for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
			if strings.HasPrefix(ref, prefix) {
				ref = strings.TrimPrefix(ref, prefix)
				break
			}
		}
		if !peerNetworkRef.MatchString(ref) {
			continue // Partial/unknown references are not expanded or followed.
		}
		flags := inventory.Object{}
		malformed, enabled := false, false
		for _, key := range []string{"importCustomRoutes", "exportCustomRoutes"} {
			if raw, exists := p[key]; exists {
				v, ok := raw.(bool)
				if !ok {
					malformed = true
					break
				}
				flags[key] = v
				enabled = enabled || v
			}
		}
		if malformed || !enabled {
			continue
		}
		out = append(out, result("info", "VPC peering requests custom-route exchange", "Review the configured peer and permitted route exchange against the intended connectivity boundary. Check effective routes and firewall policy separately; do not probe or alter peering as a test.", inventory.Object{"peering": name, "peer_network": ref, "state": "ACTIVE", "configured_flags": flags, "assessment": "Explicit local configuration on an ACTIVE peering only. Peer consent, effective connection settings, actual routes, ownership, same-organization trust, transit behavior and reachability are not established. A configured peering is not proof of lateral movement or public exposure."})...)
	}
	return out
}
