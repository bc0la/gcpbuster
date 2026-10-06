package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var apiGatewayRouteDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var apiGatewaySupportedVersion = regexp.MustCompile(`^(2\.0|3\.[01]\.[0-9]+)$`)

// apiGatewayAuth reports source configuration only; ACTIVE means ready for use,
// not that a gateway deploys this config or that a backend accepts requests.
func apiGatewayAuth(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "apigateway.googleapis.com/ApiConfig" || s(val(a, "state")) != "ACTIVE" {
		return nil
	}
	auth := obj(val(a, "_gcpbusterAuth"))
	if !apiGatewaySupportedVersion.MatchString(s(auth["version"])) {
		return nil
	}
	methods := map[string]bool{"GET": true, "PUT": true, "POST": true, "DELETE": true, "OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": s(auth["version"]) != "2.0"}
	out := []Result{}
	for _, raw := range arr(auth["routes"]) {
		r := obj(raw)
		method := s(r["method"])
		mode := s(r["auth"])
		digest := s(r["route_digest"])
		source := s(r["security_source"])
		if !methods[method] || !apiGatewayRouteDigest.MatchString(digest) || (mode != "none" && mode != "optional") || (source != "implicit" && source != "root" && source != "operation") {
			continue
		}
		out = append(out, result("medium", "API config defines an operation without required client authentication", "Review the identified OpenAPI operation and its intended audience. Require appropriate API-key or JWT security where needed, and independently enforce backend authorization. Do not invoke routes to validate this finding.", inventory.Object{"observed_active_gateways": apiGatewayDeploymentEvidence(a), "method": method, "route_digest": digest, "authentication": mode, "security_source": r["security_source"], "assessment": "A transient supported OpenAPI parse found no security requirement or an empty anonymous alternative after operation/root inheritance. This is source configuration, not verified deployment, internet reachability, successful anonymous invocation or backend authorization bypass. API keys and JWT requirements are distinguished; unknown schemes/references are not treated as anonymous. No source text, paths, credential values, backend URLs or tokens are retained. The route digest is SHA-256 of uppercase method, one space, and the document path key."})...)
	}
	return out
}
