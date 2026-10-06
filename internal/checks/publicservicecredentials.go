package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var credentialGrantResource = regexp.MustCompile(`^//iam\.googleapis\.com/projects/([A-Za-z0-9][A-Za-z0-9.:-]*)/serviceAccounts/([1-9][0-9]{5,30}|[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.-]*\.gserviceaccount\.com)$`)

// These are observed allow capabilities, never calls to the Credentials API.
// https://docs.cloud.google.com/iam/docs/service-account-permissions
func publicServiceAccountCredentials(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || !public(s(val(a, "principal"))) {
		return nil
	}
	capabilities := []struct{ permission, kind, detail string }{
		{"iam.serviceAccounts.getAccessToken", "OAuth access-token issuance", "An access token represents the target service account; downstream resource permissions and token scopes remain separate."},
		{"iam.serviceAccounts.getOpenIdToken", "OIDC ID-token issuance", "An ID token asserts identity for an audience; recipient acceptance and authorization are not established, and this is not an OAuth access token."},
		{"iam.serviceAccounts.signBlob", "blob signing", "Signing bytes is not a private-key disclosure or a demonstrated accepted credential; payload semantics and verifier trust remain separate."},
		{"iam.serviceAccounts.signJwt", "JWT signing", "Signing a JWT is not direct token issuance or private-key disclosure; claims, audience and verifier acceptance remain separate."},
	}
	project := s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project"
	if !project && (s(val(a, "resourceType")) != "iam.googleapis.com/ServiceAccount" || !credentialGrantResource.MatchString(s(val(a, "resource")))) {
		return nil
	}
	const boundary = "Observed allow-role permission only, not effective authorization. Credential APIs require accepted caller authentication; neither special principal proves tokenless access. Conditions on public principals are unsupported configuration and remain unknown, not evaluated. IAM deny, service controls, target account state and any delegation-chain prerequisites remain unresolved. No credentials were issued, bytes signed, keys fetched or downstream requests made. "
	var out []Result
	for _, capability := range capabilities {
		if !has(arr(val(a, "permissions")), capability.permission) {
			continue
		}
		if project {
			out = append(out, projectPublicCapability(a, []string{capability.permission}, "Service-account "+capability.kind, boundary+capability.detail+" Project grants are not expanded to individual service accounts.")...)
			continue
		}
		severity, condition := "high", "no condition supplied on this observation"
		if val(a, "condition") != nil {
			severity, condition = "medium", "public-principal condition supplied; unsupported/unknown applicability"
		}
		out = append(out, result(severity, "Service account grants "+capability.kind+" capability to a broad principal", "Remove unintended broad credential/signing grants; review the exact target account, conditions, caller requirements and downstream authority without issuing credentials.", inventory.Object{
			"resource": val(a, "resource"), "resource_type": val(a, "resourceType"), "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": capability.permission, "capability": capability.kind, "condition": val(a, "condition"), "condition_status": condition, "assessment": boundary + capability.detail,
		})...)
	}
	return out
}
