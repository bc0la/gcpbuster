package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func cloudBuildPRCommentControl(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "cloudbuild.googleapis.com/BuildTrigger" {
		return nil
	}
	d := a.Resource.Data
	for _, other := range []string{"triggerTemplate", "pubsubConfig", "webhookConfig"} {
		if _, present := d[other]; present {
			return nil
		}
	}
	enabled := "unknown"
	if raw, exists := d["disabled"]; exists {
		disabled, ok := raw.(bool)
		if !ok || disabled {
			return nil
		}
		enabled = "explicitly_enabled"
	}
	// Different trigger families cannot establish one coherent event when supplied together.
	fields := []string{"github", "repositoryEventConfig", "developerConnectEventConfig", "bitbucketServerTriggerConfig"}
	var config inventory.Object
	family := ""
	for _, field := range fields {
		if raw, exists := d[field]; exists {
			if family != "" {
				return nil
			}
			family = field
			config = obj(raw)
		}
	}
	if config == nil || config["push"] != nil {
		return nil
	}
	pr := obj(config["pullRequest"])
	if s(pr["commentControl"]) != "COMMENTS_DISABLED" {
		return nil
	}
	if event, exists := d["eventType"]; exists && s(event) != "REPO" && s(event) != "EVENT_TYPE_UNSPECIFIED" {
		return nil
	}
	approval := "unknown"
	severity := "info"
	if raw, exists := d["approvalConfig"]; exists {
		v, ok := obj(raw)["approvalRequired"].(bool)
		if ok {
			if v {
				approval = "required"
			} else {
				approval = "explicitly_not_required"
				severity = "medium"
			}
		}
	}
	return result(severity, "Cloud Build pull-request trigger does not require a /gcbrun comment", "Require trusted review or build approval for untrusted pull requests, and restrict build identities and secrets according to repository trust.", inventory.Object{"trigger_family": family, "comment_control": "COMMENTS_DISABLED", "trigger_enabled": enabled, "build_approval": approval, "build_trust_context": buildTrustEvidence(a), "assessment": "Explicit comment-gate configuration only: matching pull requests need no repository-writer /gcbrun authorization from this control. Repository visibility, external-contributor eligibility, branch/file filters, trigger enablement when omitted, manual approval and other controls remain independent. This does not prove anonymous access, malicious code execution or service-account compromise. COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY instead gates non-writers and is not treated as disabled. No repository contents were fetched, pull requests submitted or builds run."})
}
