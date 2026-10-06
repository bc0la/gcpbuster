package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func inheritedAuditConfig(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	enabled := map[string]bool{}
	for _, raw := range arr(val(a, "configs")) {
		c := obj(raw)
		if s(c["service"]) == "allServices" {
			enabled[s(c["logType"])] = true
		}
		if len(arr(c["exemptedMembers"])) > 0 {
			out = append(out, Result{"medium", "Inherited Data Access audit configuration contains exemptions", inventory.Object{"resource": val(a, "resource"), "service": c["service"], "log_type": c["logType"], "members": c["exemptedMembers"], "policy_sources": c["sources"], "chain_complete": val(a, "complete"), "assessment": "Union of supplied parent and local policy exemptions; inherited exemptions cannot be removed by a child setting."}, "Review principal exemptions at their originating policies and verify coverage of sensitive operations."})
		}
	}
	if b(val(a, "complete")) {
		var missing []string
		for _, typ := range []string{"ADMIN_READ", "DATA_READ", "DATA_WRITE"} {
			if !enabled[typ] {
				missing = append(missing, typ)
			}
		}
		if len(missing) > 0 {
			out = append(out, Result{"info", "Inherited policies lack a complete all-services Data Access baseline", inventory.Object{"resource": val(a, "resource"), "missing_all_services_types": missing, "policy_chain": val(a, "chain"), "assessment": "Service-specific settings and provider defaults may still enable these logs. Policy configuration does not prove actual delivery or retention; Admin Activity is separate."}, "Review per-service audit requirements and enable missing Data Access types where appropriate; verify sinks, retention and log visibility separately."})
		}
	}
	return out
}
