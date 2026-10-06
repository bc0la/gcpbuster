package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
)

const permissionSource = "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/permission-categorizations/gcp.yaml"

func permissionEvidence(a inventory.Asset) inventory.Object {
	return inventory.Object{"resource": val(a, "resource"), "resource_type": val(a, "resourceType"), "principal": val(a, "principal"), "roles": val(a, "roles"), "condition": val(a, "condition"), "catalog_sha256": permissioncatalog.SHA256(), "assessment": "configured role permission candidate; effective authorization and technique prerequisites are unverified"}
}

// Risk classifications describe capability impact, not whether this principal
// should have the permission. Group related permissions to keep broad roles usable.
func permissionRisks(a inventory.Asset, _ time.Time) []Result {
	groups := map[string][]string{}
	for _, p := range arr(val(a, "permissions")) {
		name := s(p)
		severity, ok := permissioncatalog.Severity(name)
		if !ok || (severity != "critical" && severity != "high") {
			continue
		}
		service := strings.SplitN(name, ".", 2)[0]
		key := service + "/" + severity
		groups[key] = append(groups[key], name)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Result
	for _, k := range keys {
		permissions := groups[k]
		sort.Strings(permissions)
		parts := strings.Split(k, "/")
		e := permissionEvidence(a)
		e["permissions"] = permissions
		for _, permission := range permissions {
			if permission == "secretmanager.secrets.enableManagedRotation" {
				e["supplemental_classification_reference"] = "https://docs.cloud.google.com/go/docs/reference/cloud.google.com/go/secretmanager/latest/apiv1"
				e["managed_rotation_prerequisites"] = "Capability impact only: eligible secret type, built-in identity Cloud SQL user-management grant, target applicability and effective caller authorization are not established by this permission alone. No rotation or database access was attempted."
			}
		}
		e["permission_impact_rating"] = parts[1]
		sev := "high"
		if val(a, "condition") != nil {
			sev = "medium"
		}
		out = append(out, Result{sev, fmt.Sprintf("IAM principal has %s role permissions classified %s-impact", parts[0], parts[1]), e, "Validate the principal's business need, target-resource applicability and effective controls; replace unnecessary permissions with a narrower role."})
	}
	return out
}

func permissionCombinations(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, severity := range []string{"critical", "high"} {
		for _, patterns := range permissioncatalog.Data.Combinations[severity] {
			if len(patterns) < 2 {
				continue
			}
			matches := []string{}
			complete := true
			for _, pattern := range patterns {
				found := ""
				for _, p := range arr(val(a, "permissions")) {
					if permissioncatalog.Match(pattern, s(p)) {
						found = s(p)
						break
					}
				}
				if found == "" {
					complete = false
					break
				}
				matches = append(matches, found)
			}
			if !complete {
				continue
			}
			e := permissionEvidence(a)
			e["required_permission_patterns"] = patterns
			e["matched_permissions"] = matches
			e["permission_impact_rating"] = severity
			sev := "high"
			if val(a, "condition") != nil {
				sev = "medium"
			}
			out = append(out, Result{sev, "IAM permission combination requires privilege-path review", e, "Verify each permission against its required resource and runtime identity, then break unnecessary combinations. This match alone does not prove an escalation."})
		}
	}
	return out
}

func publicPermissionCapabilities(a inventory.Asset, _ time.Time) []Result {
	if !public(s(val(a, "principal"))) {
		return nil
	}
	var permissions []string
	for _, p := range arr(val(a, "permissions")) {
		if severity, ok := permissioncatalog.Severity(s(p)); ok && (severity == "high" || severity == "critical") {
			permissions = append(permissions, s(p))
		}
	}
	if len(permissions) == 0 {
		return nil
	}
	sort.Strings(permissions)
	e := permissionEvidence(a)
	e["permissions"] = permissions
	sev := "high"
	if val(a, "condition") != nil {
		sev = "medium"
	}
	return result(sev, "Public principal's role contains high-impact capabilities", "Remove broad members or narrow the role; check resource applicability, IAM conditions and effective public-access controls.", e)
}
