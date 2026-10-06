package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func computeDiskGrant(kind, principal, permission string) inventory.Asset {
	typ := "Image"
	if kind == "snapshots" {
		typ = "Snapshot"
	}
	return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//compute.googleapis.com/projects/demo/global/" + kind + "/source", "resourceType": "compute.googleapis.com/" + typ, "principal": principal, "roles": []any{"roles/synthetic"}, "permissions": []any{permission}})
}
func TestPublicComputeDiskExactScopedPermissions(t *testing.T) {
	for _, tc := range []struct {
		kind, principal, permission string
		want                        int
	}{
		{"images", "allUsers", "compute.images.useReadOnly", 1}, {"images", "allAuthenticatedUsers", "compute.images.useReadOnly", 1}, {"snapshots", "allAuthenticatedUsers", "compute.snapshots.useReadOnly", 1}, {"snapshots", "allUsers", "compute.snapshots.useReadOnly", 1},
		{"images", "allUsers", "compute.snapshots.useReadOnly", 0}, {"snapshots", "allUsers", "compute.images.useReadOnly", 0}, {"images", "allUsers", "compute.images.get", 0}, {"snapshots", "allUsers", "compute.snapshots.list", 0}, {"images", "allUsers", "compute.images.useReadOnly.extra", 0}, {"images", "allUsers", "compute.images.*", 0}, {"images", "user:a@example.com", "compute.images.useReadOnly", 0},
	} {
		a := computeDiskGrant(tc.kind, tc.principal, tc.permission)
		got := publicComputeDiskCapabilities(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && tc.principal == "allAuthenticatedUsers" && !strings.Contains(got[0].Title, "Google-authenticated") {
			t.Fatal(got)
		}
	}
	for _, change := range []func(*inventory.Asset){func(a *inventory.Asset) { a.Type = "iam.googleapis.com/Role" }, func(a *inventory.Asset) { a.Resource.Data["resourceType"] = "compute.googleapis.com/Snapshot" }, func(a *inventory.Asset) {
		a.Resource.Data["resource"] = "//compute.googleapis.com/projects/demo/global/images/source/extra"
	}, func(a *inventory.Asset) {
		a.Resource.Data["resource"] = "//compute.googleapis.com/projects/demo/zones/us-central1-a/disks/source"
	}, func(a *inventory.Asset) {
		a.Resource.Data["resource"] = "//evil.invalid/projects/demo/global/images/source"
	}, func(a *inventory.Asset) {
		a.Resource.Data["permissions"] = []any{}
		a.Resource.Data["roles"] = []any{"roles/compute.imageUser"}
	}} {
		a := computeDiskGrant("images", "allUsers", "compute.images.useReadOnly")
		change(&a)
		if got := publicComputeDiskCapabilities(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
func TestPublicComputeDiskConditionalEvidence(t *testing.T) {
	for _, condition := range []any{inventory.Object{"expression": "false"}, inventory.Object{}, "malformed"} {
		a := computeDiskGrant("snapshots", "allUsers", "compute.snapshots.useReadOnly")
		a.Resource.Data["condition"] = condition
		got := publicComputeDiskCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Severity != "medium" || got[0].Evidence["condition"] == nil || got[0].Evidence["condition_status"] == "no condition supplied on this binding" || !strings.Contains(s(got[0].Evidence["assessment"]), "does not by itself establish") {
			t.Fatal(got)
		}
	}
}

func TestPublicComputeDiskRegionalSnapshotScope(t *testing.T) {
	for _, tc := range []struct {
		kind, resourceType, permission string
		want                           int
	}{
		{"snapshots", "compute.googleapis.com/Snapshot", "compute.snapshots.useReadOnly", 1},
		{"snapshots", "compute.googleapis.com/RegionSnapshot", "compute.snapshots.useReadOnly", 0},
		{"images", "compute.googleapis.com/Image", "compute.images.useReadOnly", 0},
	} {
		a := computeDiskGrant(tc.kind, "allAuthenticatedUsers", tc.permission)
		a.Resource.Data["resource"] = "//compute.googleapis.com/projects/demo/regions/us-central1/" + tc.kind + "/source"
		a.Resource.Data["resourceType"] = tc.resourceType
		if got := publicComputeDiskCapabilities(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestPublicComputeDiskBindingExpansion(t *testing.T) {
	image := inventory.NewAsset("//compute.googleapis.com/projects/demo/global/images/source", "compute.googleapis.com/Image", nil)
	image.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/synthetic", "members": []any{"allAuthenticatedUsers"}, "condition": inventory.Object{"expression": "false"}}}}
	role := inventory.NewAsset("//iam.googleapis.com/roles/synthetic", "iam.googleapis.com/Role", inventory.Object{"name": "roles/synthetic", "includedPermissions": []any{"compute.images.useReadOnly", "compute.snapshots.useReadOnly"}})
	unused := inventory.NewAsset("//iam.googleapis.com/roles/unassigned", "iam.googleapis.com/Role", inventory.Object{"name": "roles/unassigned", "includedPermissions": []any{"compute.images.useReadOnly"}})
	snap := inventory.Snapshot{Assets: []inventory.Asset{image, role, unused}}
	inventory.ExpandBindings(&snap)
	got := []Result{}
	for _, a := range snap.Assets {
		got = append(got, publicComputeDiskCapabilities(a, time.Now())...)
	}
	if len(got) != 1 || got[0].Evidence["permission"] != "compute.images.useReadOnly" || got[0].Evidence["resource"] != image.Name || inventory.Str(inventory.Get(got[0].Evidence, "condition", "expression")) != "false" {
		t.Fatal(got)
	}
}
