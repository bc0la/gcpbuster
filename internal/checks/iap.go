package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"time"
)

func iapAccessGrants(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, raw := range arr(a.IAM["bindings"]) {
		binding := obj(raw)
		role := s(binding["role"])
		if role != "roles/iap.httpsResourceAccessor" && role != "roles/iap.tunnelResourceAccessor" {
			continue
		}
		for _, m := range arr(binding["members"]) {
			member := s(m)
			if member == "" || strings.HasPrefix(member, "deleted:") {
				continue
			}
			sev := "info"
			title := "IAP accessor binding grants a standing access path"
			if public(member) {
				sev = "high"
				title = "IAP accessor role is granted to a public principal"
			} else if strings.HasPrefix(member, "serviceAccount:") {
				sev = "medium"
			}
			if binding["condition"] != nil && sev == "high" {
				sev = "medium"
			}
			out = append(out, Result{sev, title, inventory.Object{"member": member, "role": role, "condition": binding["condition"], "binding_resource": a.Name, "assessment": "Configured accessor grant; IAP enablement, conditions, tunnel/network reachability and backend authentication remain unverified."}, "Review resource-level IAP access separately from Compute/Run IAM. Remove unintended public or stale accessor grants and constrain legitimate access by resource and conditions."})
		}
	}
	return out
}

// An explicit disabled setting is a posture-review item, not evidence that an
// application is public or was previously protected. Missing fields are unknown.
func iapBackendProtection(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	enabled, known := inventory.Get(d, "iap", "enabled").(bool)
	if !known || enabled {
		return nil
	}
	protocol := s(d["protocol"])
	if protocol != "HTTP" && protocol != "HTTPS" && protocol != "HTTP2" {
		return nil
	}
	return []Result{{"medium", "Backend service explicitly disables IAP authentication", inventory.Object{"iap_enabled": false, "protocol": protocol, "load_balancing_scheme": d["loadBalancingScheme"], "assessment": "Configuration only; frontend reachability, other application authentication, intended public use and prior IAP state remain unverified."}, "For applications intended to require IAP, enable it and validate backend authentication and alternate ingress routes. Public applications may intentionally omit IAP."}}
}
