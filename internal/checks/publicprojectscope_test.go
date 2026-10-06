package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicServiceCapabilitiesPreserveProjectScope(t *testing.T) {
	for _, tc := range []struct {
		permission string
		eval       func(inventory.Asset, time.Time) []Result
	}{
		{"artifactregistry.repositories.downloadArtifacts", publicArtifactAccess},
		{"pubsub.topics.publish", publicPubSubCapabilities},
		{"healthcare.fhirResources.get", publicHealthcareCapabilities},
		{"secretmanager.versions.access", publicSecretPayloadCapability},
	} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudresourcemanager.googleapis.com/projects/123", "resourceType": "cloudresourcemanager.googleapis.com/Project", "principal": "allAuthenticatedUsers", "permissions": []any{tc.permission}, "condition": inventory.Object{"expression": "resource.name.startsWith('projects/demo')"}})
		got := tc.eval(a, time.Now())
		if len(got) != 1 || got[0].Severity != "medium" || got[0].Evidence["binding_scope"] != "project" || got[0].Evidence["resource"] != a.Resource.Data["resource"] {
			t.Fatal(tc.permission, got)
		}
		a.Resource.Data["resource"] = "//cloudresourcemanager.googleapis.com/projects/123/fakeChild/one"
		if len(tc.eval(a, time.Now())) != 0 {
			t.Fatal("fabricated parent path")
		}
	}
}
