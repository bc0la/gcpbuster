package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
	"regexp"
)

var buildTrustEvidenceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func buildTrustEvidence(a inventory.Asset) inventory.Object {
	out := inventory.Object{"repository_visibility": "unknown", "identity_status": "unknown", "assessment": "Repository visibility is supplied metadata only, never live GitHub verification. Direct IAM grants retain their own scope and unevaluated conditions; no contributor eligibility, build execution, token access or effective privilege is established. Missing grants do not establish least privilege; inline-build/default identities are not inferred."}
	m := obj(val(a, "_gcpbusterBuildTrust"))
	if s(m["basis"]) != "observed_configuration_and_optional_supplied_repository_metadata" {
		return out
	}
	repo := inventory.BuildTriggerRepositoryIdentityDigest(a)
	if repo != "" && s(m["repository_digest"]) == repo && s(m["repository_basis"]) == "supplied_metadata_not_live_verified" {
		switch s(m["repository_visibility"]) {
		case "public", "private", "internal":
			out["repository_visibility"] = m["repository_visibility"]
			out["repository_basis"] = "supplied_metadata_not_live_verified"
		}
	}
	email := inventory.BuildTriggerServiceAccount(a)
	if email == "" || s(m["service_account"]) != email || s(m["identity_status"]) != "explicit_trigger_service_account" {
		return out
	}
	out["identity_status"] = "explicit_trigger_service_account"
	out["service_account"] = email
	rows, ok := m["high_impact_direct_grants"].([]any)
	if !ok || len(rows) > 100 {
		return out
	}
	var safe []any
	for _, raw := range rows {
		r := obj(raw)
		if !buildTrustEvidenceDigest.MatchString(s(r["grant_resource_digest"])) {
			continue
		}
		condition := s(r["condition_status"])
		if condition != "not_supplied" && condition != "supplied_unevaluated" && condition != "malformed_unknown" {
			continue
		}
		scope := s(r["scope_kind"])
		if scope != "project" && scope != "service_account" && scope != "resource" && scope != "unknown" {
			continue
		}
		permissions, ok := r["permissions"].([]any)
		if !ok || len(permissions) > 10000 {
			continue
		}
		var selected []any
		for _, p := range permissions {
			rating, ok := permissioncatalog.Severity(s(p))
			if ok && (rating == "high" || rating == "critical") {
				selected = append(selected, s(p))
			}
		}
		if len(selected) > 0 {
			safe = append(safe, inventory.Object{"grant_resource_digest": r["grant_resource_digest"], "scope_kind": scope, "condition_status": condition, "permissions": selected})
		}
	}
	out["high_impact_direct_grants"] = safe
	if truncated, ok := m["grants_truncated"].(bool); ok {
		out["grants_truncated"] = truncated
	}
	return out
}
