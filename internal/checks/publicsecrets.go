package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var publicSecretResource = regexp.MustCompile(`^//secretmanager\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9_-]*/(?:locations/[a-z][a-z0-9-]*/)?secrets/[A-Za-z0-9_-]+$`)

func publicSecretPayloadCapability(a inventory.Asset, _ time.Time) []Result {
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"secretmanager.versions.access"}, "Secret payload access", "Project-level payload permission only; applicable secrets, inheritance, version state and effective controls must be assessed separately. Secret Manager requires accepted OAuth authentication. No payload was requested.")
	}
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "secretmanager.googleapis.com/Secret" || !publicSecretResource.MatchString(s(val(a, "resource"))) || !public(s(val(a, "principal"))) || !has(val(a, "permissions"), "secretmanager.versions.access") {
		return nil
	}
	severity, status := "high", "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		severity, status = "medium", "condition supplied; expression unverified"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	return result(severity, "Secret grants payload-access permission to a broad principal", "Remove unintended broad secret-accessor grants and independently verify conditions, version state and application dependencies.", inventory.Object{"resource": val(a, "resource"), "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": "secretmanager.versions.access", "condition": val(a, "condition"), "condition_status": status, "assessment": "Configured secret-scoped role permission only. Secret Manager requires accepted OAuth authentication; a broad principal binding does not establish tokenless access. Version availability, deny, conditions and service perimeters remain unverified. No payload was requested or credential used; metadata-viewer grants alone are not payload-access permissions."})
}
