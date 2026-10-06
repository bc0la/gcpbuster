package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var apiGatewayMCPSupportedVersion = regexp.MustCompile(`^3\.[01]\.[0-9]+$`)

func apiGatewayMCPDiscovery(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "apigateway.googleapis.com/ApiConfig" || s(val(a, "state")) != "ACTIVE" {
		return nil
	}
	if !apiGatewayMCPSupportedVersion.MatchString(s(val(a, "_gcpbusterAuth", "version"))) {
		return nil
	}
	m := obj(val(a, "_gcpbusterAuth", "mcp"))
	complete, ok := m["complete"].(bool)
	enabled, known := m["enabled"].(bool)
	if !ok || !complete || !known || !enabled || s(m["tools_list_auth"]) != "none" {
		return nil
	}
	count := 0
	switch v := m["eligible_declared_tools"].(type) {
	case int:
		count = v
	case float64:
		if v > 0 && v <= 100000 && v == float64(int(v)) {
			count = int(v)
		}
	}
	if count <= 0 || count > 100000 {
		return nil
	}
	evidence := inventory.Object{"tools_list_auth": "none", "assessment": "Supported OpenAPI 3.x source requests MCP with no tools/list authentication setting. API Gateway documents unauthenticated discovery as the default. This is not proof of deployment, reachable MCP endpoints, eligible tools, exposed names, anonymous tool invocation or backend access. Tool invocation retains underlying operation authentication; lifecycle methods are a separate documented unauthenticated surface. No tool names, descriptions, paths or source bytes are retained."}
	if gateways := apiGatewayDeploymentEvidence(a); len(gateways) > 0 {
		evidence["observed_active_gateways"] = gateways
	}
	return result("medium", "API config enables MCP discovery without configured tools/list authentication", "Review intended tool discovery visibility and configure exactly one supported JWT or x-api-key security scheme for tools/list where authentication is required. Review underlying operation authorization separately; do not invoke MCP methods to test this finding.", evidence)
}
