package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicSecretPayloadExactPermissionAndScope(t *testing.T) {
	for _, resource := range []string{"//secretmanager.googleapis.com/projects/demo/secrets/key", "//secretmanager.googleapis.com/projects/demo/locations/us-central1/secrets/key"} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": resource, "resourceType": "secretmanager.googleapis.com/Secret", "principal": "allAuthenticatedUsers", "permissions": []any{"secretmanager.versions.access"}})
		got := publicSecretPayloadCapability(a, time.Now())
		if len(got) != 1 {
			t.Fatal(got)
		}
		a.Resource.Data["permissions"] = []any{"secretmanager.secrets.get"}
		if len(publicSecretPayloadCapability(a, time.Now())) != 0 {
			t.Fatal("metadata role")
		}
		a.Resource.Data["permissions"] = []any{"secretmanager.versions.access"}
		a.Resource.Data["condition"] = inventory.Object{"expression": "true"}
		got = publicSecretPayloadCapability(a, time.Now())
		if len(got) != 1 || got[0].Severity != "medium" {
			t.Fatal(got)
		}
		a.Resource.Data["resource"] = resource + "/versions/1"
		if len(publicSecretPayloadCapability(a, time.Now())) != 0 {
			t.Fatal("wrong scope")
		}
	}
}

func TestPublicSecretPayloadProjectScope(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudresourcemanager.googleapis.com/projects/123", "resourceType": "cloudresourcemanager.googleapis.com/Project", "principal": "allUsers", "permissions": []any{"secretmanager.versions.access"}})
	got := publicSecretPayloadCapability(a, time.Now())
	if len(got) != 1 || got[0].Evidence["binding_scope"] != "project" {
		t.Fatal(got)
	}
}
