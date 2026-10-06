package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestSpannerPublicRoleReadExactConjunction(t *testing.T) {
	const db = "//spanner.googleapis.com/projects/demo/instances/instance/databases/data"
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": db, "resourceType": "spanner.googleapis.com/Database", "principal": "allAuthenticatedUsers", "permissions": []any{"spanner.databases.useRoleBasedAccess"}, "_gcpbusterSpannerPublicRole": inventory.Object{"database": db, "scope": "exact_database_schema_observation", "public_table_select_grants": 1}})
	if got := spannerPublicRoleRead(a, time.Time{}); len(got) != 1 {
		t.Fatal(got)
	}
	a.Resource.Data["permissions"] = []any{"spanner.databaseRoles.use"}
	if len(spannerPublicRoleRead(a, time.Time{})) != 0 {
		t.Fatal("membership alone")
	}
	a.Resource.Data["permissions"] = []any{"spanner.databases.useRoleBasedAccess"}
	obj(a.Resource.Data["_gcpbusterSpannerPublicRole"])["database"] = db + "other"
	if len(spannerPublicRoleRead(a, time.Time{})) != 0 {
		t.Fatal("foreign marker")
	}
	obj(a.Resource.Data["_gcpbusterSpannerPublicRole"])["database"] = db
	a.Resource.Data["principal"] = "user:person@example.com"
	if len(spannerPublicRoleRead(a, time.Time{})) != 0 {
		t.Fatal("named user")
	}
}

func TestSpannerNamedRoleRequiresUnconditionedExactBothPermissions(t *testing.T) {
	const db = "//spanner.googleapis.com/projects/demo/instances/instance/databases/data"
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": db, "resourceType": "spanner.googleapis.com/Database", "principal": "allAuthenticatedUsers", "permissions": []any{"spanner.databases.useRoleBasedAccess", "spanner.databaseRoles.use"}, "_gcpbusterSpannerPublicRole": inventory.Object{"database": db, "scope": "exact_database_schema_observation", "public_table_select_grants": 0, "named_role_select_grants": 1}})
	got := spannerPublicRoleRead(a, time.Time{})
	if len(got) != 1 || got[0].Evidence["named_role_select_conjunction"] != true {
		t.Fatal(got)
	}
	a.Resource.Data["condition"] = inventory.Object{"expression": "true"}
	if len(spannerPublicRoleRead(a, time.Time{})) != 0 {
		t.Fatal("conditional public membership")
	}
	delete(a.Resource.Data, "condition")
	a.Resource.Data["permissions"] = []any{"spanner.databases.useRoleBasedAccess"}
	if len(spannerPublicRoleRead(a, time.Time{})) != 0 {
		t.Fatal("missing role membership")
	}
}
