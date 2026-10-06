package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func artifactDownloadGrant(principal string, permission string) inventory.Asset {
	return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//artifactregistry.googleapis.com/projects/demo/locations/us-central1/repositories/repo", "resourceType": "artifactregistry.googleapis.com/Repository", "principal": principal, "roles": []any{"roles/customReader"}, "permissions": []any{permission}})
}

func TestPublicArtifactRequiresDirectResolvedDownloadCapability(t *testing.T) {
	for _, tc := range []struct {
		principal, permission string
		want                  int
	}{
		{"allUsers", "artifactregistry.repositories.downloadArtifacts", 1},
		{"allAuthenticatedUsers", "artifactregistry.repositories.downloadArtifacts", 1},
		{"user:one@example.com", "artifactregistry.repositories.downloadArtifacts", 0},
		{"allUsers", "artifactregistry.repositories.get", 0},
		{"allUsers", "artifactregistry.repositories.list", 0},
		{"allUsers", "artifactregistry.repositories.readViaVirtualRepository", 0},
		{"allUsers", "artifactregistry.repositories.downloadArtifacts.extra", 0},
	} {
		a := artifactDownloadGrant(tc.principal, tc.permission)
		got := publicArtifactAccess(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && got[0].Evidence["principal"] != tc.principal {
			t.Fatal(got)
		}
		if tc.principal == "allAuthenticatedUsers" && len(got) > 0 && !strings.Contains(got[0].Title, "Google-authenticated") {
			t.Fatal(got)
		}
	}
	for _, change := range []func(*inventory.Asset){
		func(a *inventory.Asset) { a.Type = "iam.googleapis.com/Role" },
		func(a *inventory.Asset) {
			a.Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
		},
		func(a *inventory.Asset) {
			a.Resource.Data["resource"] = "//artifactregistry.googleapis.com/projects/demo/locations/us/repositories/repo/extra"
		},
		func(a *inventory.Asset) {
			a.Resource.Data["resource"] = "//evil.invalid/projects/demo/locations/us/repositories/repo"
		},
	} {
		a := artifactDownloadGrant("allUsers", "artifactregistry.repositories.downloadArtifacts")
		change(&a)
		if got := publicArtifactAccess(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}

func TestPublicArtifactPreservesConditionalAndMalformedEvidence(t *testing.T) {
	for _, condition := range []any{inventory.Object{"expression": "false", "title": "never"}, inventory.Object{}, "malformed"} {
		a := artifactDownloadGrant("allUsers", "artifactregistry.repositories.downloadArtifacts")
		a.Resource.Data["condition"] = condition
		got := publicArtifactAccess(a, time.Now())
		if len(got) != 1 || got[0].Evidence["condition"] == nil || got[0].Evidence["condition_status"] == "no condition supplied on this binding" {
			t.Fatal(got)
		}
	}
}

func TestPublicArtifactBindingExpansionKeepsScopeAndCondition(t *testing.T) {
	repo := inventory.NewAsset("//artifactregistry.googleapis.com/projects/demo/locations/us-central1/repositories/repo", "artifactregistry.googleapis.com/Repository", nil)
	repo.IAM = inventory.Object{"bindings": []any{
		inventory.Object{"role": "roles/download", "members": []any{"allUsers"}, "condition": inventory.Object{"expression": "false"}},
		inventory.Object{"role": "roles/metadata", "members": []any{"allAuthenticatedUsers"}},
	}}
	role := func(name, permission string) inventory.Asset {
		return inventory.NewAsset("//iam.googleapis.com/"+name, "iam.googleapis.com/Role", inventory.Object{"name": name, "includedPermissions": []any{permission}})
	}
	s := inventory.Snapshot{Assets: []inventory.Asset{repo, role("roles/download", "artifactregistry.repositories.downloadArtifacts"), role("roles/metadata", "artifactregistry.repositories.get"), role("roles/unassigned", "artifactregistry.repositories.downloadArtifacts")}}
	inventory.ExpandBindings(&s)
	findings := []Result{}
	for _, a := range s.Assets {
		findings = append(findings, publicArtifactAccess(a, time.Now())...)
	}
	if len(findings) != 1 || findings[0].Evidence["resource"] != repo.Name || inventory.Str(inventory.Get(findings[0].Evidence, "condition", "expression")) != "false" {
		t.Fatal(findings)
	}
}
