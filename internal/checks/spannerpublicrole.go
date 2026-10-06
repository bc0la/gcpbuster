package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var spannerPublicGrant = regexp.MustCompile(`^//spanner\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9_-]*/instances/[a-z][a-z0-9-]*/databases/[A-Za-z][A-Za-z0-9_-]*$`)

func spannerPublicRoleRead(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "spanner.googleapis.com/Database" || !spannerPublicGrant.MatchString(s(val(a, "resource"))) || !public(s(val(a, "principal"))) || !has(arr(val(a, "permissions")), "spanner.databases.useRoleBasedAccess") {
		return nil
	}
	d := obj(val(a, "_gcpbusterSpannerPublicRole"))
	n, ok := apigeeStepCount(d["public_table_select_grants"])
	if !ok || n < 0 || n > 10000 || d["database"] != val(a, "resource") || d["scope"] != "exact_database_schema_observation" {
		return nil
	}
	named := 0
	if v, exists := d["named_role_select_grants"]; exists {
		var valid bool
		named, valid = apigeeStepCount(v)
		if !valid || named > 10000 {
			return nil
		}
	}
	// An unconditioned databaseRoles.use grant on this database permits all
	// its roles; never interpret public conditional role selectors as valid.
	namedEligible := named > 0 && val(a, "condition") == nil && has(arr(val(a, "permissions")), "spanner.databaseRoles.use")
	if n == 0 && !namedEligible {
		return nil
	}
	condition := "none supplied"
	if val(a, "condition") != nil {
		condition = "public-principal conditional binding unsupported; applicability unknown"
	}
	title := "Broad Spanner FGAC grant coincides with SELECT granted to SQL public role"
	if n == 0 {
		title = "Broad Spanner all-role FGAC grant coincides with named-role SELECT privileges"
	}
	return result("medium", title, "Review the broad IAM permission and table/column SELECT privileges granted to database roles; do not open sessions or read rows to test access.", inventory.Object{"resource": val(a, "resource"), "principal": val(a, "principal"), "permission": "spanner.databases.useRoleBasedAccess", "public_table_select_grants": n, "named_role_select_conjunction": namedEligible, "condition_status": condition, "assessment": "Observed same-database IAM/schema conjunction only. SELECT may be whole-table or column-scoped, not every row/column. The SQL public role is inherited by fine-grained users; it is not the IAM allUsers principal. Named-role conjunction requires unconditioned databaseRoles.use alongside useRoleBasedAccess on this exact database, not a conditional selector or inherited project grant. Accepted authentication, role selection, current schema, IAM deny/conditions and effective authorization are not established. Public-principal grantability is not inferred from generic CLI syntax. No role graph, quoted grantee, compound-privilege or PostgreSQL semantics expanded. No session, SQL execution, rows, tokens or schema changes occurred."})
}
