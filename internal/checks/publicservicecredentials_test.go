package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func credentialTestGrant() inventory.Asset {
	return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//iam.googleapis.com/projects/demo/serviceAccounts/test@demo.iam.gserviceaccount.com", "resourceType": "iam.googleapis.com/ServiceAccount", "principal": "allAuthenticatedUsers", "permissions": []any{"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.actAs"}})
}

func TestPublicServiceCredentialsExactCapabilitiesAndScope(t *testing.T) {
	a := credentialTestGrant()
	got := publicServiceAccountCredentials(a, time.Time{})
	if len(got) != 4 {
		t.Fatal(got)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.Evidence["permission"].(string)] = true
		if r.Severity != "high" || !strings.Contains(r.Evidence["assessment"].(string), "No credentials were issued") {
			t.Fatal(r)
		}
	}
	if len(seen) != 4 || seen["iam.serviceAccounts.actAs"] {
		t.Fatal(seen)
	}
	a.Resource.Data["resource"] = "//iam.googleapis.com/projects/123456/serviceAccounts/123456789012345678901"
	if len(publicServiceAccountCredentials(a, time.Time{})) != 4 {
		t.Fatal("canonical UID")
	}
	a.Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
	a.Resource.Data["resource"] = "//cloudresourcemanager.googleapis.com/projects/demo"
	got = publicServiceAccountCredentials(a, time.Time{})
	if len(got) != 4 || got[0].Evidence["binding_scope"] != "project" {
		t.Fatal(got)
	}
}

func TestPublicServiceCredentialsRejectsUnboundAndPreservesUnknown(t *testing.T) {
	for _, resource := range []string{"//iam.googleapis.com/projects/-/serviceAccounts/1234567", "//iam.googleapis.com/projects/demo/serviceAccounts/../x", "//iam.googleapis.com/projects/demo/serviceAccounts/test@example.com", "//iam.googleapis.com/projects/demo/serviceAccounts/123456/keys/k", "//storage.googleapis.com/bucket"} {
		a := credentialTestGrant()
		a.Resource.Data["resource"] = resource
		if len(publicServiceAccountCredentials(a, time.Time{})) != 0 {
			t.Fatal(resource)
		}
	}
	a := credentialTestGrant()
	a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
	got := publicServiceAccountCredentials(a, time.Time{})
	if len(got) != 4 || got[0].Severity != "medium" || !strings.Contains(got[0].Evidence["condition_status"].(string), "unknown") {
		t.Fatal(got)
	}
	a.Resource.Data["principal"] = "user:person@example.com"
	if len(publicServiceAccountCredentials(a, time.Time{})) != 0 {
		t.Fatal("named principal")
	}
	a = credentialTestGrant()
	a.Resource.Data["permissions"] = []any{"iam.serviceAccounts.get", "iam.serviceAccounts.actAs"}
	if len(publicServiceAccountCredentials(a, time.Time{})) != 0 {
		t.Fatal("metadata/actAs not credentials")
	}
	a = credentialTestGrant()
	a.Type = "iam.googleapis.com/Role"
	if len(publicServiceAccountCredentials(a, time.Time{})) != 0 {
		t.Fatal("unassigned role")
	}
}
