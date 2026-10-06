package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestPublicStorageCapabilitiesDistinctActions(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//storage.googleapis.com/example-bucket", "resourceType": "storage.googleapis.com/Bucket", "principal": "allUsers", "permissions": []any{"storage.objects.get", "storage.objects.list", "storage.objects.create", "storage.objects.delete", "storage.objects.get"}})
	got := publicStorageCapabilities(a, time.Now())
	if len(got) != 4 {
		t.Fatal(got)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.Evidence["permission"].(string)] = true
		if !strings.Contains(r.Evidence["assessment"].(string), "Public access prevention can override") {
			t.Fatal(r)
		}
	}
	if len(seen) != 4 {
		t.Fatal(got)
	}
	a.Resource.Data["permissions"] = []any{"storage.objects.create"}
	got = publicStorageCapabilities(a, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Evidence["assessment"].(string), "Create alone does not allow overwriting") {
		t.Fatal(got)
	}
	a.Resource.Data["principal"] = "allAuthenticatedUsers"
	a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
	got = publicStorageCapabilities(a, time.Now())
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatal(got)
	}
}

func TestPublicStorageCapabilitiesResourceAndProjectBoundaries(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//storage.googleapis.com/example-bucket/object", "resourceType": "storage.googleapis.com/Bucket", "principal": "allUsers", "permissions": []any{"storage.objects.get"}})
	if len(publicStorageCapabilities(a, time.Now())) != 0 {
		t.Fatal("object is not bucket")
	}
	a.Resource.Data["resource"] = "//cloudresourcemanager.googleapis.com/projects/demo"
	a.Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
	got := publicStorageCapabilities(a, time.Now())
	if len(got) != 1 || got[0].Evidence["binding_scope"] != "project" {
		t.Fatal(got)
	}
	a.Resource.Data["permissions"] = []any{"storage.buckets.get", "storage.buckets.list"}
	if len(publicStorageCapabilities(a, time.Now())) != 0 {
		t.Fatal("bucket metadata not object access")
	}
}

func TestPublicStorageCapabilitiesObservedPAPOverridesBinding(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//storage.googleapis.com/example-bucket", "resourceType": "storage.googleapis.com/Bucket", "principal": "allUsers", "permissions": []any{"storage.objects.get"}})
	for _, tc := range []struct{ state, severity string }{{"enforced", "info"}, {"inherited", "high"}, {"unknown", "high"}} {
		a.Resource.Data["_gcpbusterStorageControls"] = inventory.Object{"bucket": "//storage.googleapis.com/example-bucket", "scope": "exact_bucket_metadata", "status": "observed", "public_access_prevention": tc.state}
		got := publicStorageCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Severity != tc.severity || got[0].Evidence["public_access_prevention"] != tc.state {
			t.Fatal(tc, got)
		}
	}
	for _, control := range []inventory.Object{{"bucket": "//storage.googleapis.com/other-bucket", "scope": "exact_bucket_metadata", "status": "observed", "public_access_prevention": "enforced"}, {"bucket": "//storage.googleapis.com/example-bucket", "scope": "exact_bucket_metadata", "status": "conflicting", "public_access_prevention": "enforced"}, {"bucket": "//storage.googleapis.com/example-bucket", "scope": "exact_bucket_metadata", "status": "observed", "uniform_bucket_level_access": true}} {
		a.Resource.Data["_gcpbusterStorageControls"] = control
		if got := publicStorageCapabilities(a, time.Now()); got[0].Severity != "high" || got[0].Evidence["public_access_prevention"] != "unknown" {
			t.Fatal("foreign/conflicting/UBLA evidence suppressed binding review", got)
		}
	}
}
