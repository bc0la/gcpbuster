package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"reflect"
	"testing"
	"time"
)

func TestParameterAuditEnablementAndUnknownEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"absent", `{}`, 0},
		{"missing-configs", `{"complete":true}`, 0},
		{"incomplete", `{"complete":false,"configs":[]}`, 0},
		{"disabled-complete", `{"complete":true,"configs":[]}`, 1},
		{"enabled-service", `{"complete":true,"configs":[{"service":"parametermanager.googleapis.com","logType":"DATA_READ"}]}`, 0},
		{"enabled-inherited", `{"complete":true,"configs":[{"service":"allServices","logType":"DATA_READ"}]}`, 0},
		{"secret-only", `{"complete":true,"configs":[{"service":"secretmanager.googleapis.com","logType":"DATA_READ"}]}`, 1},
		{"admin-only", `{"complete":true,"configs":[{"service":"parametermanager.googleapis.com","logType":"ADMIN_READ"}]}`, 1},
		{"malformed-config", `{"complete":true,"configs":[null]}`, 0},
		{"malformed-exemptions", `{"complete":true,"configs":[{"service":"parametermanager.googleapis.com","logType":"DATA_READ","exemptedMembers":42}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parameterManagerAudit(asset(inventory.AuditConfigType, tc.body), time.Time{})
			if len(got) != tc.want {
				t.Fatal(tc, got)
			}
			for _, r := range got {
				if r.Evidence["service"] != "parametermanager.googleapis.com" || r.Evidence["log_type"] != "DATA_READ" || r.Evidence["render_performed"] != false || r.Evidence["reference_resolution_performed"] != false {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestParameterAuditExemptionsKnownPartialUnion(t *testing.T) {
	body := `{"complete":false,"configs":[{"service":"allServices","logType":"DATA_READ","exemptedMembers":["user:z@example.invalid"]},{"service":"parametermanager.googleapis.com","logType":"DATA_READ","exemptedMembers":["group:a@example.invalid","user:z@example.invalid"]},{"service":"secretmanager.googleapis.com","logType":"DATA_READ","exemptedMembers":["user:ignore@example.invalid"]}]}`
	got := parameterManagerAudit(asset(inventory.AuditConfigType, body), time.Time{})
	if len(got) != 1 || got[0].Evidence["complete_policy_chain"] != false || !reflect.DeepEqual(got[0].Evidence["members"], []string{"group:a@example.invalid", "user:z@example.invalid"}) {
		t.Fatal(got)
	}
}

func TestParameterAuditInheritedResolverIntegration(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/p", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": "organizations/123"})
		project.IAM = inventory.Object{}
		org := inventory.NewAsset("//cloudresourcemanager.googleapis.com/organizations/123", "cloudresourcemanager.googleapis.com/Organization", inventory.Object{})
		org.IAM = inventory.Object{}
		if inherited {
			org.IAM["auditConfigs"] = []any{inventory.Object{"service": "allServices", "auditLogConfigs": []any{inventory.Object{"logType": "DATA_READ"}}}}
		}
		snap := inventory.Snapshot{Assets: []inventory.Asset{project, org}}
		inventory.ResolveAuditConfigs(&snap)
		found := false
		for _, a := range snap.Assets {
			if a.Type != inventory.AuditConfigType || inventory.Str(a.Resource.Data["resource"]) != project.Name {
				continue
			}
			found = true
			want := 1
			if inherited {
				want = 0
			}
			if got := parameterManagerAudit(a, time.Time{}); len(got) != want {
				t.Fatal(inherited, got)
			}
		}
		if !found {
			t.Fatal("missing resolved project audit config")
		}
	}
}
