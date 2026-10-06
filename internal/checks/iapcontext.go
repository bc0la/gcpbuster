package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
)

var iapContextBackend = regexp.MustCompile(`^//compute\.googleapis\.com/projects/[A-Za-z0-9_-]+/(global|regions/([a-z][a-z0-9-]*))/backendServices/([a-z][-a-z0-9]*)$`)
var iapContextBinding = regexp.MustCompile(`^//iap\.googleapis\.com/(projects/[0-9]+)/iap_web/compute(?:-([a-z][a-z0-9-]*))?/services/([A-Za-z0-9_-]+)$`)

func iapBackendContextEvidence(a inventory.Asset, resource string) inventory.Object {
	unknown := inventory.Object{"status": "not_correlated"}
	c := obj(val(a, "_gcpbusterIAPBackendContext"))
	scope, status := s(c["scope"]), s(c["status"])
	if scope != "exact_backend_id_metadata" && scope != "exact_backend_name_metadata" {
		return unknown
	}
	if status == "ambiguous" || status == "missing_context" {
		return inventory.Object{"status": status, "scope": scope}
	}
	if status != "observed" || s(c["binding_resource"]) != resource {
		return unknown
	}
	backend := s(c["resource"])
	m := iapContextBackend.FindStringSubmatch(backend)
	b := iapContextBinding.FindStringSubmatch(resource)
	typ := s(c["resource_type"])
	if m == nil || b == nil || s(c["project_number"]) != b[1] || m[2] != b[2] || (m[1] == "global" && typ != "compute.googleapis.com/BackendService") || (m[1] != "global" && typ != "compute.googleapis.com/RegionBackendService") {
		return unknown
	}
	if (scope == "exact_backend_id_metadata" && s(c["backend_id"]) != b[3]) || (scope == "exact_backend_name_metadata" && m[3] != b[3]) {
		return unknown
	}
	result := inventory.Object{"status": "observed", "scope": scope, "backend_resource": backend, "backend_type": typ}
	if flag, ok := c["iap_enabled"].(bool); ok {
		result["iap_enabled"] = flag
	}
	for _, field := range []string{"protocol", "loadBalancingScheme"} {
		value := s(c[field])
		allowed := []string{"HTTP", "HTTPS", "HTTP2", "TCP", "SSL", "UDP", "GRPC", "H2C", "UNSPECIFIED"}
		if field == "loadBalancingScheme" {
			allowed = []string{"EXTERNAL", "EXTERNAL_MANAGED", "INTERNAL", "INTERNAL_MANAGED", "INTERNAL_SELF_MANAGED", "INVALID_LOAD_BALANCING_SCHEME"}
		}
		for _, candidate := range allowed {
			if candidate == value {
				result[field] = value
				break
			}
		}
	}
	return result
}
