package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"sort"
	"strings"
)

var apiConfigEvidenceName = regexp.MustCompile(`^//apigateway\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/locations/global/apis/[a-z]([-a-z0-9]{0,61}[a-z0-9])?/configs/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Project only canonical same-project references. These remain observations,
// not a fresh data-plane verification or evidence that every rollout is active.
func serviceConfigPinEvidence(a inventory.Asset) []any {
	byConfig := map[string]map[string]bool{}
	for _, entry := range arr(val(a, "_gcpbusterGatewayPins")) {
		p := obj(entry)
		config := s(p["apiConfig"])
		if !apiConfigEvidenceName.MatchString(config) {
			continue
		}
		project := strings.Split(config, "/")[4]
		if project != s(val(a, "producerProjectId")) {
			continue
		}
		for _, raw := range arr(p["gateways"]) {
			gateway := s(raw)
			if !gatewayEvidenceName.MatchString(gateway) || strings.Split(gateway, "/")[4] != project {
				continue
			}
			if byConfig[config] == nil {
				byConfig[config] = map[string]bool{}
			}
			byConfig[config][gateway] = true
		}
	}
	names := []string{}
	for name := range byConfig {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []any{}
	for _, name := range names {
		gateways := []string{}
		for gateway := range byConfig[name] {
			gateways = append(gateways, gateway)
		}
		sort.Strings(gateways)
		refs := []any{}
		for _, gateway := range gateways {
			refs = append(refs, gateway)
		}
		out = append(out, inventory.Object{"api_config": name, "observed_active_gateways": refs})
	}
	return out
}
