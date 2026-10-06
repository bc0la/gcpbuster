package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"sort"
)

var gatewayEvidenceName = regexp.MustCompile(`^//apigateway\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/locations/[a-z][a-z0-9-]*/gateways/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

func apiGatewayDeploymentEvidence(a inventory.Asset) []any {
	seen := map[string]bool{}
	for _, raw := range arr(val(a, "_gcpbusterGateways")) {
		if name := s(raw); gatewayEvidenceName.MatchString(name) {
			seen[name] = true
		}
	}
	names := []string{}
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	refs := []any{}
	for _, name := range names {
		refs = append(refs, name)
	}
	return refs
}
