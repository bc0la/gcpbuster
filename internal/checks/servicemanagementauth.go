package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func serviceManagementAuth(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/ServiceConfig" {
		return nil
	}
	projection := obj(val(a, "_gcpbusterServiceAuth"))
	out := []Result{}
	for _, raw := range arr(projection["methods"]) {
		m := obj(raw)
		digest := s(m["method_digest"])
		authSource := s(m["authentication_source"])
		usageSource := s(m["usage_source"])
		if !apiGatewayRouteDigest.MatchString(digest) || m["authentication"] != "none" || m["consumer_identity"] != "not_required" || (authSource != "default" && authSource != "rule") || usageSource != "rule" {
			continue
		}
		out = append(out, result("medium", "Compiled service method has no configured client credential requirement", "Review the identified method's intended audience and configure authentication and consumer identity requirements where appropriate. Independently enforce backend authorization; do not invoke methods to test this finding.", inventory.Object{"rollout_history": serviceConfigHistoryEvidence(a), "observed_gateway_pins": serviceConfigPinEvidence(a), "observed_esp_config_pins": serviceConfigESPPinEvidence(a), "authentication_source": authSource, "usage_source": usageSource, "method_digest": digest, "assessment": "Last-matching rules and documented compiled-config defaults resolve no OAuth/JWT requirement; an explicit usage rule allows unregistered calls. Absent authentication rules default to no authentication; absent usage rules require consumer identity. This analysis assumes complete compiled authentication and usage fields from the collector. This is compiled configuration, not proof of deployment, reachability, anonymous invocation, or backend authorization bypass. Method names and rule contents are not retained. Digest is SHA-256 of fully qualified API name, a dot, and simple method name."})...)
	}
	return out
}
