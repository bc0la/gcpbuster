package checks

import (
	"reflect"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestSQLUserUpdateAuditPolicyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"missing", `{}`, 0},
		{"incomplete", `{"complete":false,"configs":[]}`, 0},
		{"disabled", `{"complete":true,"configs":[]}`, 1},
		{"service enabled", `{"complete":true,"configs":[{"service":"cloudsql.googleapis.com","logType":"DATA_WRITE"}]}`, 0},
		{"all enabled", `{"complete":true,"configs":[{"service":"allServices","logType":"DATA_WRITE"}]}`, 0},
		{"wrong hostname", `{"complete":true,"configs":[{"service":"sqladmin.googleapis.com","logType":"DATA_WRITE"}]}`, 1},
		{"secret enabled", `{"complete":true,"configs":[{"service":"secretmanager.googleapis.com","logType":"DATA_WRITE"}]}`, 1},
		{"read not write", `{"complete":true,"configs":[{"service":"cloudsql.googleapis.com","logType":"DATA_READ"}]}`, 1},
		{"malformed class", `{"complete":true,"configs":[{"service":"cloudsql.googleapis.com","logType":"INVALID"}]}`, 0},
		{"malformed exemptions", `{"complete":true,"configs":[{"service":"cloudsql.googleapis.com","logType":"DATA_WRITE","exemptedMembers":false}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudSQLUserUpdateAudit(asset(inventory.AuditConfigType, tc.body), time.Time{})
			if len(got) != tc.want {
				t.Fatal(tc, got)
			}
			for _, r := range got {
				if r.Evidence["method"] != "cloudsql.users.update" || r.Evidence["sql_password_update_performed"] != false {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestSQLUserUpdateAuditPartialExemptions(t *testing.T) {
	body := `{"complete":false,"configs":[{"service":"allServices","logType":"DATA_WRITE","exemptedMembers":["user:z@example.test"]},{"service":"cloudsql.googleapis.com","logType":"DATA_WRITE","exemptedMembers":["group:a@example.test","user:z@example.test"]},{"service":"cloudsql.googleapis.com","logType":"DATA_READ","exemptedMembers":["user:ignored@example.test"]}]}`
	got := cloudSQLUserUpdateAudit(asset(inventory.AuditConfigType, body), time.Time{})
	if len(got) != 1 || got[0].Evidence["complete_policy_chain"] != false || !reflect.DeepEqual(got[0].Evidence["members"], []string{"group:a@example.test", "user:z@example.test"}) {
		t.Fatal(got)
	}
}

func TestSQLUserUpdateAuditInheritedResolver(t *testing.T) {
	for _, mode := range []string{"missing ancestor", "disabled complete", "enabled ancestor"} {
		project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/p", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": "organizations/123"})
		project.IAM = inventory.Object{}
		org := inventory.NewAsset("//cloudresourcemanager.googleapis.com/organizations/123", "cloudresourcemanager.googleapis.com/Organization", inventory.Object{})
		org.IAM = inventory.Object{}
		snap := inventory.Snapshot{Assets: []inventory.Asset{project}}
		if mode != "missing ancestor" {
			if mode == "enabled ancestor" {
				org.IAM["auditConfigs"] = []any{inventory.Object{"service": "allServices", "auditLogConfigs": []any{inventory.Object{"logType": "DATA_WRITE"}}}}
			}
			snap.Assets = append(snap.Assets, org)
		}
		inventory.ResolveAuditConfigs(&snap)
		found := false
		for _, a := range snap.Assets {
			if a.Type != inventory.AuditConfigType || a.Resource.Data["resource"] != project.Name {
				continue
			}
			found = true
			want := 0
			if mode == "disabled complete" {
				want = 1
			}
			if got := cloudSQLUserUpdateAudit(a, time.Time{}); len(got) != want {
				t.Fatal(mode, got)
			}
		}
		if !found {
			t.Fatal("missing project audit row")
		}
	}
}
