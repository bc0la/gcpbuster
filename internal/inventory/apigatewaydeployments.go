package inventory

import (
	"sort"
	"strings"
)

// This is a join of explicit control-plane observations, not a reachability
// test. Missing bindings never establish that a config is undeployed.
func correlateAPIGatewayDeployments(out *Snapshot, projectID, number string) {
	bindings := map[string]map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "apigateway.googleapis.com/Gateway" || Str(a.Resource.Data["state"]) != "ACTIVE" {
			continue
		}
		_, gateway, err := viewerAPIGatewayProjection(a.Resource.Data, projectID, number, "Gateway")
		if err != nil || a.Name != "//apigateway.googleapis.com/"+gateway {
			continue
		}
		ref := Str(a.Resource.Data["apiConfig"])
		_, config, err := viewerAPIGatewayProjection(Object{"name": ref}, projectID, number, "ApiConfig")
		if err != nil {
			continue
		}
		if bindings[config] == nil {
			bindings[config] = map[string]bool{}
		}
		bindings[config][a.Name] = true
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "apigateway.googleapis.com/ApiConfig" || !strings.HasPrefix(a.Name, "//apigateway.googleapis.com/projects/"+projectID+"/") {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterGateways")
		_, config, err := viewerAPIGatewayProjection(a.Resource.Data, projectID, number, "ApiConfig")
		if err != nil || a.Name != "//apigateway.googleapis.com/"+config {
			continue
		}
		names := []string{}
		for name := range bindings[config] {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > 0 {
			refs := []any{}
			for _, name := range names {
				refs = append(refs, name)
			}
			a.Resource.Data["_gcpbusterGateways"] = refs
		}
	}
}
