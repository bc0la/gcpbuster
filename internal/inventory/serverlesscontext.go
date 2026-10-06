package inventory

import "reflect"

// Join existing current metadata to the exact invoker-grant resource. Parent
// grants, numeric/name aliases and v2 Function-to-Run links are not guessed.
func CorrelateServerlessContext(snap *Snapshot) {
	contexts := map[string]Object{}
	conflicts := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != "run.googleapis.com/Service" && a.Type != "cloudfunctions.googleapis.com/CloudFunction" {
			continue
		}
		if Str(a.Resource.Data["name"]) == "" || "//"+serviceHost(a.Type)+"/"+Str(a.Resource.Data["name"]) != a.Name {
			continue
		}
		c := Object{"resource": a.Name, "resource_type": a.Type, "status": "observed", "http_trigger": "unknown", "ingress": "unknown"}
		if a.Type == "run.googleapis.com/Service" {
			c["http_trigger"] = "service_configuration"
			if ingress, ok := a.Resource.Data["ingress"].(string); ok && (ingress == "INGRESS_TRAFFIC_ALL" || ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" || ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER") {
				c["ingress"] = ingress
			}
			for _, key := range []string{"invokerIamDisabled", "iapEnabled"} {
				if flag, ok := a.Resource.Data[key].(bool); ok {
					c[key] = flag
				}
			}
		} else {
			if ingress, ok := a.Resource.Data["ingressSettings"].(string); ok && (ingress == "ALLOW_ALL" || ingress == "ALLOW_INTERNAL_ONLY" || ingress == "ALLOW_INTERNAL_AND_GCLB") {
				c["ingress"] = ingress
			}
			http, hp := a.Resource.Data["httpsTrigger"]
			event, ep := a.Resource.Data["eventTrigger"]
			if hp && !ep && Obj(http) != nil {
				c["http_trigger"] = "http_configuration"
			} else if ep && !hp && Str(Obj(event)["eventType"]) != "" {
				c["http_trigger"] = "event_driven_configuration"
			}
		}
		key := a.Type + "|" + a.Name
		if previous, present := contexts[key]; present && !reflect.DeepEqual(previous, c) {
			conflicts[key] = true
		}
		contexts[key] = c
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != PermissionGrantType {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterServerlessContext")
		key := Str(a.Resource.Data["resourceType"]) + "|" + Str(a.Resource.Data["resource"])
		if conflicts[key] {
			a.Resource.Data["_gcpbusterServerlessContext"] = Object{"status": "conflicting"}
		} else if c := contexts[key]; c != nil {
			a.Resource.Data["_gcpbusterServerlessContext"] = c
		}
	}
}

func serviceHost(typ string) string {
	if typ == "run.googleapis.com/Service" {
		return "run.googleapis.com"
	}
	return "cloudfunctions.googleapis.com"
}
