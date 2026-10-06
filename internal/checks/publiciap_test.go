package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicIAPExactPermissionsAndCanonicalScopes(t *testing.T) {
	for _, tc := range []struct{ path, permission string }{
		{"iap_web", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/compute/services/backend", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/compute-us-central1/services/123", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/appengine-demo/services/default/versions/v1", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/cloud_run-us-central1/services/app", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/forwarding_rule/services/rule", "iap.webServiceVersions.accessViaIAP"},
		{"iap_tunnel", "iap.tunnelInstances.accessViaIAP"},
		{"iap_tunnel/zones/us-central1-a/instances/vm", "iap.tunnelInstances.accessViaIAP"},
		{"iap_tunnel/locations/us-central1/destGroups/group", "iap.tunnelDestGroups.accessViaIAP"},
	} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//iap.googleapis.com/projects/123/" + tc.path, "resourceType": "iap.googleapis.com/PolicyResource", "principal": "allUsers", "permissions": []any{tc.permission}, "roles": []any{"projects/demo/roles/customIAP"}})
		got := publicIAPCapabilities(a, time.Now())
		if len(got) != 1 {
			t.Fatal(tc, got)
		}
		a.Resource.Data["condition"] = inventory.Object{"expression": "true"}
		got = publicIAPCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Severity != "info" {
			t.Fatal(got)
		}
		a.Resource.Data["permissions"] = []any{"iap.webServices.accessViaIAP", "iap.webServices.getIamPolicy"}
		if len(publicIAPCapabilities(a, time.Now())) != 0 {
			t.Fatal("wrong permission")
		}
	}
}

func TestPublicIAPCrossProductAndMalformedRejected(t *testing.T) {
	for _, tc := range []struct{ path, permission string }{
		{"iap_web/compute/services/backend", "iap.tunnelInstances.accessViaIAP"},
		{"iap_tunnel/zones/us-central1-a", "iap.webServiceVersions.accessViaIAP"},
		{"iap_tunnel/locations/us-central1/destGroups/group", "iap.tunnelInstances.accessViaIAP"},
		{"iap_web/compute/services/backend/versions/v1", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/unknown/services/app", "iap.webServiceVersions.accessViaIAP"},
		{"iap_web/compute/services/../bad", "iap.webServiceVersions.accessViaIAP"},
	} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//iap.googleapis.com/projects/123/" + tc.path, "resourceType": "iap.googleapis.com/PolicyResource", "principal": "allAuthenticatedUsers", "permissions": []any{tc.permission}})
		if len(publicIAPCapabilities(a, time.Now())) != 0 {
			t.Fatal(tc)
		}
	}
}

func TestPublicIAPProjectScopeNoChildExpansion(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudresourcemanager.googleapis.com/projects/123", "resourceType": "cloudresourcemanager.googleapis.com/Project", "principal": "allAuthenticatedUsers", "permissions": []any{"iap.webServiceVersions.accessViaIAP", "iap.tunnelInstances.accessViaIAP"}})
	got := publicIAPCapabilities(a, time.Now())
	if len(got) != 2 || got[0].Evidence["binding_scope"] != "project" {
		t.Fatal(got)
	}
	a.Resource.Data["principal"] = "user:private@example.com"
	if len(publicIAPCapabilities(a, time.Now())) != 0 {
		t.Fatal("not public")
	}
}
