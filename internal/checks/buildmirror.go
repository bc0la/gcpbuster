package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func cloudBuildMirroredSource(a inventory.Asset, _ time.Time) []Result {
	if !inventory.BuildTriggerCSRMirrorConfigured(a) {
		return nil
	}
	enabled := "unknown"
	if raw, exists := a.Resource.Data["disabled"]; exists {
		disabled, ok := raw.(bool)
		if !ok || disabled {
			return nil
		}
		enabled = "explicitly_enabled"
	}
	d := obj(val(a, "triggerTemplate"))
	revision := ""
	count := 0
	for _, field := range []string{"branchName", "tagName", "commitSha"} {
		if raw, exists := d[field]; exists {
			text, ok := raw.(string)
			if !ok || text == "" || len(text) > 4096 {
				return nil
			}
			revision = field
			count++
		}
	}
	if count != 1 {
		return nil
	}
	approval := "unknown"
	if v, ok := val(a, "approvalConfig", "approvalRequired").(bool); ok {
		if v {
			approval = "required"
		} else {
			approval = "explicitly_not_required"
		}
	}
	return result("info", "Cloud Build trigger references a configured external repository mirror", "Review upstream write authority, mirror health, branch/tag and file filters, build approvals and the explicit build identity as a supply-chain trust boundary.", inventory.Object{"source": "cloud_source_repositories_mirror", "trigger_enabled": enabled, "revision_selector": revision, "build_approval": approval, "build_trust_context": buildTrustEvidence(a), "assessment": "Observed CSR mirrorConfig metadata is bound to this trigger's explicit source reference. External repository visibility, if supplied, is not external write authority. Mirror synchronization, upstream webhook/deploy credentials, branch protections, filter matching, current source content and actual build execution are unverified. No cloning, provider request, token access or build submission occurred."})
}
