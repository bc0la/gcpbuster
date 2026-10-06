package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
)

func TestIAPBackendContextEvidenceTypedAndBound(t *testing.T) {
	resource := "//iap.googleapis.com/projects/123/iap_web/compute/services/456"
	context := inventory.Object{"status": "observed", "scope": "exact_backend_id_metadata", "binding_resource": resource, "resource": "//compute.googleapis.com/projects/demo/global/backendServices/web", "resource_type": "compute.googleapis.com/BackendService", "iap_enabled": false, "protocol": "HTTPS", "loadBalancingScheme": "EXTERNAL_MANAGED", "oauth2ClientSecret": "PRIVATE_VALUE"}
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"_gcpbusterIAPBackendContext": context})
	context["project_number"] = "projects/123"
	context["backend_id"] = "456"
	got := iapBackendContextEvidence(a, resource)
	if got["status"] != "observed" || got["iap_enabled"] != false || got["oauth2ClientSecret"] != nil {
		t.Fatal(got)
	}
	context["binding_resource"] = "foreign"
	if got := iapBackendContextEvidence(a, resource); got["status"] != "not_correlated" {
		t.Fatal("foreign context trusted", got)
	}
	context["binding_resource"] = resource
	for _, field := range []string{"project_number", "backend_id"} {
		prior := context[field]
		context[field] = "foreign"
		if got := iapBackendContextEvidence(a, resource); got["status"] != "not_correlated" {
			t.Fatal("foreign scope trusted", field, got)
		}
		context[field] = prior
	}
	context["resource"] = "//compute.googleapis.com/projects/demo/regions/us-central1/backendServices/web"
	context["resource_type"] = "compute.googleapis.com/RegionBackendService"
	if got := iapBackendContextEvidence(a, resource); got["status"] != "not_correlated" {
		t.Fatal("regional backend trusted for global binding", got)
	}
	context["resource"] = "//compute.googleapis.com/projects/demo/global/backendServices/web"
	context["resource_type"] = "compute.googleapis.com/BackendService"
	context["iap_enabled"] = "false"
	if got := iapBackendContextEvidence(a, resource); got["iap_enabled"] != nil {
		t.Fatal("unknown bool became disabled", got)
	}
}
