package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func rotationFixture() []inventory.Asset {
	name := "//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/db"
	uid := "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/opaque"
	secret := inventory.NewAsset(name, "secretmanager.googleapis.com/Secret", inventory.Object{"name": strings.TrimPrefix(name, "//secretmanager.googleapis.com/"), "secretType": "CLOUD_SQL_DB_CREDENTIALS", "policyMember": inventory.Object{"iamPolicyUidPrincipal": uid}, "rotation": inventory.Object{"managedRotationStatus": inventory.Object{"state": "INACTIVE"}}})
	secret.Ancestors = []string{"projects/123", "folders/456", "organizations/789"}
	caller := inventory.NewAsset("caller", inventory.PermissionGrantType, inventory.Object{"principal": "user:reader@example.test", "resource": "//cloudresourcemanager.googleapis.com/projects/123", "permissions": []any{"secretmanager.secrets.enableManagedRotation"}})
	sql := inventory.NewAsset("sql", inventory.PermissionGrantType, inventory.Object{"principal": uid, "resource": "//cloudresourcemanager.googleapis.com/projects/999", "permissions": []any{"cloudsql.users.list", "cloudsql.users.update"}})
	return []inventory.Asset{secret, caller, sql}
}

func TestManagedRotationPrerequisiteComposition(t *testing.T) {
	for _, scope := range []string{"projects/123", "//cloudresourcemanager.googleapis.com/projects/123", "folders/456", "organizations/789", rotationFixture()[0].Name} {
		assets := rotationFixture()
		assets[1].Resource.Data["resource"] = scope
		assets[1].Resource.Data["condition"] = inventory.Object{"expression": "false"}
		assets[2].Resource.Data["condition"] = inventory.Object{"expression": "request.time < timestamp('2000-01-01T00:00:00Z')"}
		rows := ManagedRotationPrerequisiteAssets(assets)
		if len(rows) != 1 {
			t.Fatalf("scope %s: %v", scope, rows)
		}
		findings := secretManagerLifecycle(rows[0], time.Now())
		if len(findings) != 1 || findings[0].Severity != "medium" || findings[0].Evidence["sql_grant_resource"] != "//cloudresourcemanager.googleapis.com/projects/999" || !strings.Contains(findings[0].Evidence["assessment"].(string), "one-shot") || findings[0].Evidence["caller_condition"] == nil || findings[0].Evidence["sql_condition"] == nil {
			t.Fatal(findings)
		}
	}
}

func TestManagedRotationPrerequisiteRejectsUnprovenJoins(t *testing.T) {
	for _, name := range []string{"unrelated caller scope", "caller missing permission", "sql missing list", "wrong UID", "name not UID", "wrong region", "global", "wrong type", "wrong identity name", "conflicting secret", "split SQL different scopes", "unknown SQL scope", "unobserved folder"} {
		t.Run(name, func(t *testing.T) {
			a := rotationFixture()
			switch name {
			case "unrelated caller scope":
				a[1].Resource.Data["resource"] = "projects/777"
			case "caller missing permission":
				a[1].Resource.Data["permissions"] = []any{"secretmanager.secrets.rotate"}
			case "sql missing list":
				a[2].Resource.Data["permissions"] = []any{"cloudsql.users.update"}
			case "wrong UID":
				a[2].Resource.Data["principal"] = "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/other"
			case "name not UID":
				a[2].Resource.Data["principal"] = "principal://secretmanager.googleapis.com/projects/123/name/locations/us-central1/secrets/db"
			case "wrong region":
				a[0].Resource.Location = "us-east1"
			case "global":
				a[0].Name = strings.Replace(a[0].Name, "us-central1", "global", 1)
			case "wrong type":
				a[0].Resource.Data["secretType"] = "GENERIC"
			case "wrong identity name":
				a[0].Resource.Data["name"] = "projects/123/locations/us-central1/secrets/other"
			case "conflicting secret":
				b := inventory.NewAsset(a[0].Name, a[0].Type, inventory.Object{"secretType": "GENERIC"})
				a = append(a, b)
			case "split SQL different scopes":
				b := inventory.NewAsset("sql2", inventory.PermissionGrantType, inventory.Object{"principal": a[2].Resource.Data["principal"], "resource": "projects/777", "permissions": []any{"cloudsql.users.list"}})
				a[2].Resource.Data["permissions"] = []any{"cloudsql.users.update"}
				a = append(a, b)
			case "unknown SQL scope":
				a[2].Resource.Data["resource"] = "//sqladmin.googleapis.com/projects/999/instances/db"
			case "unobserved folder":
				a[1].Resource.Data["resource"] = "folders/555"
			}
			if rows := ManagedRotationPrerequisiteAssets(a); len(rows) != 0 {
				t.Fatal(rows)
			}
		})
	}
}

func TestManagedRotationSplitSQLGrantsPreserveIndependentConditions(t *testing.T) {
	a := rotationFixture()
	a[2].Resource.Data["permissions"] = []any{"cloudsql.users.update"}
	a[2].Resource.Data["condition"] = inventory.Object{"expression": "false"}
	b := inventory.NewAsset("sql-list", inventory.PermissionGrantType, inventory.Object{"principal": a[2].Resource.Data["principal"], "resource": "projects/999", "permissions": []any{"cloudsql.users.list"}, "condition": inventory.Object{"expression": "true"}})
	a = append(a, b)
	rows := ManagedRotationPrerequisiteAssets(a)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	d := rows[0].Resource.Data
	if inventory.Get(d, "sql_condition", "expression") != "false" || inventory.Get(d, "sql_list_condition", "expression") != "true" || d["sql_list_grant"] != "sql-list" {
		t.Fatal(d)
	}
}
