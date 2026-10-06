package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestWorkloadRiskRequiresClassifiedGrant(t *testing.T) {
	for _, tc := range []struct {
		permission string
		want       int
	}{{"iam.serviceAccountKeys.create", 1}, {"storage.objects.list", 0}, {"not.a.real.permission", 0}} {
		a := inventory.NewAsset("workload", inventory.WorkloadGrantType, inventory.Object{"permissions": []any{tc.permission}, "condition": inventory.Object{"expression": "never-assume-true"}, "oauthScopes": []any{"read-only"}})
		got := workloadIdentityGrants(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (got[0].Evidence["condition"] == nil || got[0].Evidence["oauth_scopes"] == nil) {
			t.Fatal("lost limiting evidence")
		}
	}
}

func TestManagedSecretGrantEvidenceDoesNotInventServiceAccountOrSQLTarget(t *testing.T) {
	for _, kind := range []string{"resource_uid", "resource_name"} {
		a := inventory.NewAsset("secret/grant", inventory.WorkloadGrantType, inventory.Object{"workload": "//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/secret", "workloadType": "secretmanager.googleapis.com/Secret", "principal": "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/opaque-uid", "identityKind": kind, "identityField": "policyMember.iamPolicyUidPrincipal", "grantResource": "projects/other", "permissions": []any{"cloudsql.users.update"}, "condition": inventory.Object{"expression": "false"}})
		got := workloadIdentityGrants(a, time.Now())
		if len(got) != 1 {
			t.Fatal(got)
		}
		e := got[0].Evidence
		if _, exists := e["service_account"]; exists {
			t.Fatal(e)
		}
		if e["principal"] != a.Resource.Data["principal"] || e["identity_kind"] != kind || e["grant_resource"] != "projects/other" || inventory.Str(inventory.Get(e, "condition", "expression")) != "false" || !strings.Contains(inventory.Str(e["assessment"]), "Cloud SQL target") {
			t.Fatal(e)
		}
	}
}
