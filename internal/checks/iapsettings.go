package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func iapSettings(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	var out []Result
	add := func(severity, title, field string, value any, remediation string) {
		out = append(out, Result{severity, title, inventory.Object{"field": field, "configured_value": value, "assessment": "Explicit local setting; inheritance, intended application policy and runtime enforcement are not resolved."}, remediation})
	}
	if enabled, ok := inventory.Get(d, "accessSettings", "corsSettings", "allowHttpOptions").(bool); ok && enabled {
		add("medium", "IAP allows OPTIONS requests without authentication", "accessSettings.corsSettings.allowHttpOptions", true, "Confirm the application safely handles unauthenticated OPTIONS and requires this CORS behavior. Disable this exception if unnecessary; it does not bypass authentication for all HTTP methods.")
	}
	if xs := arr(inventory.Get(d, "accessSettings", "oauthSettings", "programmaticClients")); len(xs) > 0 {
		valid := true
		for _, x := range xs {
			if s(x) == "" {
				valid = false
			}
		}
		if valid {
			add("info", "IAP permits configured programmatic OAuth clients", "accessSettings.oauthSettings.programmaticClients.count", len(xs), "Review each allowed client and its ownership against intended programmatic access. This configuration alone does not grant IAM access.")
		}
	}
	if s(inventory.Get(d, "accessSettings", "reauthSettings", "method")) == "METHOD_UNSPECIFIED" {
		add("info", "Local IAP setting disables reauthentication", "accessSettings.reauthSettings.method", "METHOD_UNSPECIFIED", "Review effective ancestor minimum policies and the application's reauthentication requirements before concluding reauthentication is disabled at runtime.")
	}
	if enabled, ok := inventory.Get(d, "accessSettings", "allowedDomainsSettings", "enable").(bool); ok && !enabled {
		add("info", "Local IAP allowed-domain restriction is disabled", "accessSettings.allowedDomainsSettings.enable", false, "Verify the intended identity restrictions and effective settings. Domain hints are not an authorization boundary; review IAM independently.")
	}
	return out
}
