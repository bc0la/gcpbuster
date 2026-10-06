package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func appEngineProtection(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	status := s(d["servingStatus"])
	if status == "USER_DISABLED" || status == "SYSTEM_DISABLED" {
		return nil
	}
	if status != "SERVING" && status != "UNSPECIFIED" {
		status = "unknown"
	}
	enabled, known := inventory.Get(d, "iap", "enabled").(bool)
	if !known || enabled {
		return nil
	}
	return []Result{{"medium", "App Engine application explicitly disables IAP", inventory.Object{"iap_enabled": false, "serving_status": status, "assessment": "Configuration only; intended public use, ingress/firewall and application authentication remain unverified."}, "Enable IAP where required by the application's access policy, or document and verify alternative authentication. This setting alone does not establish public access."}}
}

func appEngineIngress(a inventory.Asset, _ time.Time) []Result {
	ingress := s(inventory.Get(a.Resource.Data, "networkSettings", "ingressTrafficAllowed"))
	if ingress != "INGRESS_TRAFFIC_ALLOWED_ALL" && ingress != "INGRESS_TRAFFIC_ALLOWED_UNSPECIFIED" {
		return nil
	}
	return []Result{{"info", "App Engine service ingress permits public sources", inventory.Object{"ingress_setting": ingress, "assessment": "Ingress configuration only. IAP, App Engine firewall, serving state and application authentication may still restrict access; no endpoint request performed."}, "For services intended to be private or load-balancer-only, restrict ingress and validate alternate service/version hostnames. Public applications may intentionally allow this setting."}}
}
