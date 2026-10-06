package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
	"sort"
	"time"
)

func workloadIdentityGrants(a inventory.Asset, _ time.Time) []Result {
	var risks []string
	for _, p := range arr(val(a, "permissions")) {
		name := s(p)
		rating, ok := permissioncatalog.Severity(name)
		if ok && (rating == "high" || rating == "critical") {
			risks = append(risks, name)
		}
	}
	if len(risks) == 0 {
		return nil
	}
	sort.Strings(risks)
	evidence := inventory.Object{"workload": val(a, "workload"), "workload_type": val(a, "workloadType"), "principal": val(a, "principal"), "identity_kind": val(a, "identityKind"), "identity_field": val(a, "identityField"), "oauth_scopes": val(a, "oauthScopes"), "grant_resource": val(a, "grantResource"), "roles": val(a, "roles"), "permissions": risks, "condition": val(a, "condition"), "catalog_sha256": permissioncatalog.SHA256(), "assessment": "Configured identity-to-grant relationship only. No code execution, token retrieval or effective privilege escalation is established; templates do not imply running instances."}
	remediation := "Review the workload's attached identity and grant scope; minimize unnecessary permissions. Validate who can modify/run the workload and whether actAs, OAuth scopes, conditions and runtime controls allow the proposed path."
	if kind := s(val(a, "identityKind")); kind == "resource_uid" || kind == "resource_name" {
		evidence["assessment"] = "Exact built-in regional Secret Manager principal-to-direct-grant correlation only. UID and name principals are not interchangeable; resource recreation has different grant semantics. The Cloud SQL target, active rotation, credential validity and effective authorization are not established. No payload, token or database connection was accessed."
		remediation = "Review the built-in secret principal's exact UID/name binding, condition and granting resource. Limit unnecessary configured capabilities; independently verify rotation prerequisites and the intended database target without assuming a service-account or impersonation path."
	} else {
		evidence["service_account"] = val(a, "serviceAccount")
	}
	return result("medium", "Workload identity has high-impact configured IAM capabilities", remediation, evidence)
}
