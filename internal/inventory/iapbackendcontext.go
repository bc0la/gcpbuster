package inventory

import (
	"reflect"
	"regexp"
	"strings"
)

var iapBackendContextResource = regexp.MustCompile(`^//iap\.googleapis\.com/(projects/[0-9]+)/iap_web/(compute|compute-([a-z][a-z0-9-]*))/services/([0-9]+|[a-z](?:[-a-z0-9]*[a-z0-9])?)$`)
var iapBackendComputeResource = regexp.MustCompile(`^//compute\.googleapis\.com/projects/([A-Za-z0-9_-]+)/(global|regions/([a-z][a-z0-9-]*))/backendServices/([a-z]([-a-z0-9]*[a-z0-9])?)$`)

// CorrelateIAPBackendContext does not collect IAP policies or expand parents.
// It joins independently observed/supplied grants with exact IDs or names and
// explicit project identities. This is configuration context, not invocation.
func CorrelateIAPBackendContext(snap *Snapshot) {
	aliases := map[string]string{}
	badAlias := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != "cloudresourcemanager.googleapis.com/Project" {
			continue
		}
		number := Str(a.Resource.Data["name"])
		id := Str(a.Resource.Data["projectId"])
		if !projectNumberPattern.MatchString(number) || a.Name != "//cloudresourcemanager.googleapis.com/"+number || !viewerResourceName.MatchString(id) {
			continue
		}
		if old := aliases[id]; old != "" && old != number {
			badAlias[id] = true
		}
		aliases[id] = number
	}
	contexts := map[string]Object{}
	conflicts := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != "compute.googleapis.com/BackendService" && a.Type != "compute.googleapis.com/RegionBackendService" {
			continue
		}
		m := iapBackendComputeResource.FindStringSubmatch(a.Name)
		if m == nil || len(m[4]) > 63 || Str(a.Resource.Data["name"]) != m[4] {
			continue
		}
		regional := m[3] != ""
		if regional != (a.Type == "compute.googleapis.com/RegionBackendService") {
			continue
		}
		location := "global"
		if regional {
			location = m[3]
		}
		if a.Resource.Location != "" && a.Resource.Location != location {
			continue
		}
		number := ""
		ambiguous := false
		for _, p := range a.Ancestors {
			if projectNumberPattern.MatchString(p) {
				if number != "" && number != p {
					ambiguous = true
				}
				number = p
			}
		}
		if number == "" || ambiguous {
			continue
		}
		if "projects/"+m[1] != number && (badAlias[m[1]] || aliases[m[1]] != number) {
			continue
		}
		id, idOK := viewerComputeUint64(a.Resource.Data["id"])
		part := "compute"
		if regional {
			part += "-" + m[3]
		}
		prefix := "//iap.googleapis.com/" + number + "/iap_web/" + part + "/services/"
		c := Object{"status": "observed", "resource": a.Name, "resource_type": a.Type, "project_number": number}
		if idOK {
			c["backend_id"] = id
		}
		if v, ok := Get(a.Resource.Data, "iap", "enabled").(bool); ok {
			c["iap_enabled"] = v
		}
		for _, field := range []string{"protocol", "loadBalancingScheme"} {
			v := Str(a.Resource.Data[field])
			allowed := "GRPC,H2C,HTTP,HTTP2,HTTPS,SSL,TCP,UDP,UNSPECIFIED"
			if field == "loadBalancingScheme" {
				allowed = "EXTERNAL,EXTERNAL_MANAGED,INTERNAL,INTERNAL_MANAGED,INTERNAL_SELF_MANAGED,INVALID_LOAD_BALANCING_SCHEME"
			}
			for _, x := range strings.Split(allowed, ",") {
				if x == v {
					c[field] = v
					break
				}
			}
		}
		identifiers := map[string]string{m[4]: "exact_backend_name_metadata"}
		if idOK {
			identifiers[id] = "exact_backend_id_metadata"
		}
		for identifier, scope := range identifiers {
			key := prefix + identifier
			selected := Object{}
			for k, v := range c {
				selected[k] = v
			}
			selected["scope"] = scope
			selected["binding_resource"] = key
			if old := contexts[key]; old != nil && !reflect.DeepEqual(old, selected) {
				conflicts[key] = true
			}
			contexts[key] = selected
		}
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != PermissionGrantType {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterIAPBackendContext")
		if Str(a.Resource.Data["resourceType"]) != "iap.googleapis.com/PolicyResource" {
			continue
		}
		resource := Str(a.Resource.Data["resource"])
		m := iapBackendContextResource.FindStringSubmatch(resource)
		if m == nil {
			continue
		}
		scope := "exact_backend_name_metadata"
		if m[4][0] >= '0' && m[4][0] <= '9' {
			if _, ok := viewerComputeUint64(m[4]); !ok {
				continue
			}
			scope = "exact_backend_id_metadata"
		} else if len(m[4]) > 63 {
			continue
		}
		context := Object{"status": "missing_context", "scope": scope, "binding_resource": resource, "project_number": m[1]}
		if conflicts[resource] {
			context["status"] = "ambiguous"
		} else if c := contexts[resource]; c != nil {
			context = c
		}
		a.Resource.Data["_gcpbusterIAPBackendContext"] = context
	}
}
