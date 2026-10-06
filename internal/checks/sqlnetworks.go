package checks

import (
	"net"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

// A configured ACL is not proof of a reachable database. The SQL API defines
// REQUIRED connector enforcement as disabling existing authorized networks.
// https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances
func sqlAuthorizedNetworks(a inventory.Asset, now time.Time) []Result {
	if s(val(a, "settings", "connectorEnforcement")) == "REQUIRED" {
		return nil
	}
	var out []Result
	for _, raw := range arr(val(a, "settings", "ipConfiguration", "authorizedNetworks")) {
		entry := obj(raw)
		_, network, err := net.ParseCIDR(s(entry["value"]))
		if err != nil {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones != 0 {
			continue
		}
		severity, title := "high", "Cloud SQL authorizes an internet-wide network"
		evidence := inventory.Object{"network": entry["value"], "assessment": "Configured authorized-network grant only; public/private connectivity, connectors, credentials and other controls still determine effective access."}
		if rawExpiry, exists := entry["expirationTime"]; exists {
			expiry, isString := rawExpiry.(string)
			if isString && expiry == "" { // API can omit an unset expiration or emit an empty string.
			} else if deadline, err := time.Parse(time.RFC3339Nano, expiry); isString && err == nil {
				if !deadline.After(now) {
					continue
				}
				evidence["expiration_time"] = deadline.UTC().Format(time.RFC3339Nano)
			} else {
				severity, title = "medium", "Cloud SQL internet-wide network has an unverified expiration"
				evidence["expiration_status"] = "malformed; current grant validity is unknown"
			}
		}
		out = append(out, Result{severity, title, evidence, "Review current network requirements and replace unnecessary internet-wide entries with specific trusted networks."})
	}
	return out
}
