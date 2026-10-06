package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var bigQueryGrantResource = regexp.MustCompile(`^//bigquery\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9_-]*/datasets/([A-Za-z0-9_]+)(?:/tables/([\p{L}\p{M}\p{N}\p{Pc}\p{Pd}\p{Zs}]+))?$`)

func publicBigQueryCapabilities(a inventory.Asset, _ time.Time) []Result {
	// BigQuery documents authenticated cross-account readers, not a tokenless
	// allUsers dataset read path. Do not promote unsupported supplied bindings.
	if a.Type != inventory.PermissionGrantType || s(val(a, "principal")) != "allAuthenticatedUsers" || !has(arr(val(a, "permissions")), "bigquery.tables.getData") {
		return nil
	}
	detail := "Exact resolved bigquery.tables.getData allow permission only, not effective data access. BigQuery API calls require accepted OAuth authentication. Direct tabledata.list requires table getData but no query job; SQL queries independently require bigquery.jobs.create in the execution/billing project, not necessarily the data owner's project. Conditions, IAM deny, row-level security, policy tags, data masking and service perimeters remain unverified. Dataset/project scope does not identify accessible child tables. Indexed or supplied policy observations can be incomplete; no queries, table rows or exports were requested."
	typ := s(val(a, "resourceType"))
	if typ == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"bigquery.tables.getData"}, "BigQuery authenticated table-read", detail)
	}
	m := bigQueryGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil || len(m[1]) > 1024 || utf8.RuneCountInString(m[2]) > 1024 {
		return nil
	}
	scope := ""
	switch {
	case typ == "bigquery.googleapis.com/Dataset" && m[2] == "":
		scope = "dataset"
	case typ == "bigquery.googleapis.com/Table" && m[2] != "":
		scope = "table"
	default:
		return nil
	}
	severity, status := "high", "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		severity, status = "medium", "condition supplied; not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	return result(severity, "BigQuery "+scope+" grants table-read permission to all authenticated users", "Review intended public datasets and remove unintended cross-account reader grants; verify conditions and table-level controls without reading data.", inventory.Object{"resource": val(a, "resource"), "resource_type": typ, "binding_scope": scope, "principal": "allAuthenticatedUsers", "permission": "bigquery.tables.getData", "roles": val(a, "roles"), "condition": val(a, "condition"), "condition_status": status, "assessment": detail})
}
