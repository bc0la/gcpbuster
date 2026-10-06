package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"reflect"
	"testing"
	"time"
)

func TestSecretAuditEnablementUnionAndCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"complete-empty", `{"complete":true,"configs":[]}`, 2},
		{"incomplete-empty", `{"complete":false,"configs":[]}`, 0},
		{"missing-complete", `{"configs":[]}`, 0},
		{"malformed-complete", `{"complete":"true","configs":[]}`, 0},
		{"missing-configs", `{"complete":true}`, 0},
		{"null-configs", `{"complete":true,"configs":null}`, 0},
		{"all-services", `{"complete":true,"configs":[{"service":"allServices","logType":"ADMIN_READ"},{"service":"allServices","logType":"DATA_READ"}]}`, 0},
		{"service-specific", `{"complete":true,"configs":[{"service":"secretmanager.googleapis.com","logType":"ADMIN_READ"},{"service":"secretmanager.googleapis.com","logType":"DATA_READ"}]}`, 0},
		{"mixed", `{"complete":true,"configs":[{"service":"allServices","logType":"ADMIN_READ"},{"service":"secretmanager.googleapis.com","logType":"DATA_READ"}]}`, 0},
		{"data-read-not-admin", `{"complete":true,"configs":[{"service":"allServices","logType":"DATA_READ"}]}`, 1},
		{"admin-not-data-read", `{"complete":true,"configs":[{"service":"secretmanager.googleapis.com","logType":"ADMIN_READ"}]}`, 1},
		{"data-write-does-not-cover", `{"complete":true,"configs":[{"service":"allServices","logType":"DATA_WRITE"}]}`, 2},
		{"other-service", `{"complete":true,"configs":[{"service":"storage.googleapis.com","logType":"ADMIN_READ"}]}`, 2},
		{"malformed-row", `{"complete":true,"configs":[null]}`, 0},
		{"unknown-class", `{"complete":true,"configs":[{"service":"allServices","logType":"INVALID"}]}`, 0},
		{"malformed-members", `{"complete":true,"configs":[{"service":"allServices","logType":"ADMIN_READ","exemptedMembers":false}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := secretManagerAudit(asset(inventory.AuditConfigType, tc.body), time.Now())
			if len(got) != tc.want {
				t.Fatalf("want %d: %+v", tc.want, got)
			}
			for _, r := range got {
				if r.Evidence["assessment"] == nil || r.Evidence["complete_policy_chain"] != true {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestSecretAuditExemptionsUnionPartialAndDeterministic(t *testing.T) {
	body := `{"complete":false,"configs":[{"service":"allServices","logType":"ADMIN_READ","exemptedMembers":["user:z@example.com","group:a@example.com"]},{"service":"secretmanager.googleapis.com","logType":"ADMIN_READ","exemptedMembers":["group:a@example.com"]},{"service":"secretmanager.googleapis.com","logType":"DATA_READ","exemptedMembers":["user:z@example.com"]},{"service":"storage.googleapis.com","logType":"DATA_READ","exemptedMembers":["user:ignored@example.com"]}]}`
	got := secretManagerAudit(asset(inventory.AuditConfigType, body), time.Now())
	if len(got) != 2 || got[0].Evidence["log_type"] != "ADMIN_READ" || got[1].Evidence["log_type"] != "DATA_READ" {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(got[0].Evidence["members"], []string{"group:a@example.com", "user:z@example.com"}) || got[0].Evidence["complete_policy_chain"] != false {
		t.Fatal(got)
	}
}

func TestSecretAuditResolverIntegration(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/p", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": "organizations/123"})
		project.IAM = inventory.Object{}
		org := inventory.NewAsset("//cloudresourcemanager.googleapis.com/organizations/123", "cloudresourcemanager.googleapis.com/Organization", inventory.Object{})
		org.IAM = inventory.Object{}
		if inherited {
			org.IAM["auditConfigs"] = []any{inventory.Object{"service": "allServices", "auditLogConfigs": []any{inventory.Object{"logType": "ADMIN_READ"}, inventory.Object{"logType": "DATA_READ"}}}}
		}
		snap := inventory.Snapshot{Assets: []inventory.Asset{project, org}}
		inventory.ResolveAuditConfigs(&snap)
		found := false
		for _, a := range snap.Assets {
			if a.Type != inventory.AuditConfigType || inventory.Str(a.Resource.Data["resource"]) != project.Name {
				continue
			}
			found = true
			got := secretManagerAudit(a, time.Now())
			want := 2
			if inherited {
				want = 0
			}
			if len(got) != want {
				t.Fatalf("inherited=%v: %+v", inherited, got)
			}
		}
		if !found {
			t.Fatal("resolver produced no project audit record")
		}
	}
}
