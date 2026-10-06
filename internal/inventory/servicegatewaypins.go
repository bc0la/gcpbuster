package inventory

import (
	"sort"
	"strings"
)

// correlateServiceGatewayPins joins observed ACTIVE gateway pins to a compiled
// service config through its API's explicit managedService. No rollout inferred.
func correlateServiceGatewayPins(out *Snapshot, projectID, number string) {
	observations := map[string]string{}
	ambiguous := map[string]bool{}
	for _, a := range out.Assets {
		value := ""
		switch a.Type {
		case "apigateway.googleapis.com/Gateway":
			value = Str(a.Resource.Data["state"]) + "|" + Str(a.Resource.Data["apiConfig"])
		case "apigateway.googleapis.com/ApiConfig":
			value = Str(a.Resource.Data["serviceConfigId"])
		default:
			continue
		}
		key := a.Type + "|" + a.Name
		if old, exists := observations[key]; exists && old != value {
			ambiguous[key] = true
		}
		observations[key] = value
	}
	apis := map[string]string{}
	conflicts := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "apigateway.googleapis.com/Api" {
			continue
		}
		clean, name, err := viewerAPIGatewayProjection(a.Resource.Data, projectID, number, "Api")
		service := Str(clean["managedService"])
		if err != nil || a.Name != "//apigateway.googleapis.com/"+name || !viewerManagedServiceName.MatchString(service) {
			continue
		}
		if old, exists := apis[name]; exists && old != service {
			conflicts[name] = true
		}
		apis[name] = service
	}
	// Revalidate live observations instead of trusting an arbitrary derived array.
	gateways := map[string]string{}
	for _, a := range out.Assets {
		if a.Type != "apigateway.googleapis.com/Gateway" || Str(a.Resource.Data["state"]) != "ACTIVE" || ambiguous[a.Type+"|"+a.Name] {
			continue
		}
		_, name, err := viewerAPIGatewayProjection(a.Resource.Data, projectID, number, "Gateway")
		if err != nil || a.Name != "//apigateway.googleapis.com/"+name {
			continue
		}
		_, config, err := viewerAPIGatewayProjection(Object{"name": a.Resource.Data["apiConfig"]}, projectID, number, "ApiConfig")
		if err == nil {
			gateways[a.Name] = "//apigateway.googleapis.com/" + config
		}
	}
	pins := map[string]map[string]map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "apigateway.googleapis.com/ApiConfig" || ambiguous[a.Type+"|"+a.Name] {
			continue
		}
		clean, name, err := viewerAPIGatewayProjection(a.Resource.Data, projectID, number, "ApiConfig")
		if err != nil || a.Name != "//apigateway.googleapis.com/"+name {
			continue
		}
		parent := name[:strings.LastIndex(name, "/configs/")]
		service := apis[parent]
		id := Str(clean["serviceConfigId"])
		if conflicts[parent] || service == "" || !viewerManagedConfigID.MatchString(id) {
			continue
		}
		target := "//servicemanagement.googleapis.com/services/" + service + "/configs/" + id
		for _, raw := range List(a.Resource.Data["_gcpbusterGateways"]) {
			gateway := Str(raw)
			if gateways[gateway] != a.Name {
				continue
			}
			if pins[target] == nil {
				pins[target] = map[string]map[string]bool{}
			}
			if pins[target][a.Name] == nil {
				pins[target][a.Name] = map[string]bool{}
			}
			pins[target][a.Name][gateway] = true
		}
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != ServiceConfigType || Str(a.Resource.Data["producerProjectId"]) != projectID {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterGatewayPins")
		service, id := Str(a.Resource.Data["name"]), Str(a.Resource.Data["id"])
		if !viewerManagedServiceName.MatchString(service) || !viewerManagedConfigID.MatchString(id) || a.Name != "//servicemanagement.googleapis.com/services/"+service+"/configs/"+id {
			continue
		}
		names := []string{}
		for name := range pins[a.Name] {
			names = append(names, name)
		}
		sort.Strings(names)
		rows := []any{}
		for _, name := range names {
			refs := []string{}
			for ref := range pins[a.Name][name] {
				refs = append(refs, ref)
			}
			sort.Strings(refs)
			values := []any{}
			for _, ref := range refs {
				values = append(values, ref)
			}
			rows = append(rows, Object{"apiConfig": name, "gateways": values})
		}
		if len(rows) > 0 {
			a.Resource.Data["_gcpbusterGatewayPins"] = rows
		}
	}
}
