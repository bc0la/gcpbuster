package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var modelArmorTemplateName = regexp.MustCompile(`^//modelarmor\.googleapis\.com/projects/[0-9]+/locations/[a-z][a-z0-9-]*/templates/[A-Za-z0-9_-]+$`)

func modelArmorFilterConfiguration(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/ModelArmorTemplate" || !modelArmorTemplateName.MatchString(a.Name) {
		return nil
	}
	if raw, present := a.Resource.Data["projection_complete"]; present {
		if complete, ok := raw.(bool); !ok || !complete {
			return nil
		}
	}
	var observations []any
	f := obj(val(a, "filterConfig"))
	for _, tc := range []struct{ field, label string }{{"piAndJailbreakFilterSettings", "prompt_injection_and_jailbreak"}, {"maliciousUriFilterSettings", "malicious_uri"}} {
		cfg := obj(f[tc.field])
		if mode, ok := cfg["filterEnforcement"].(string); ok && mode == "DISABLED" {
			observations = append(observations, inventory.Object{"filter": tc.label, "enforcement": "DISABLED"})
		}
		if tc.field == "piAndJailbreakFilterSettings" && cfg["filterEnforcement"] == "ENABLED" && cfg["confidenceLevel"] == "HIGH" {
			observations = append(observations, inventory.Object{"filter": tc.label, "enforcement": "ENABLED", "confidence_threshold": "HIGH"})
		}
	}
	sdp := obj(f["sdpSettings"])
	if _, advanced := sdp["advancedConfig"]; !advanced && s(obj(sdp["basicConfig"])["filterEnforcement"]) == "DISABLED" {
		observations = append(observations, inventory.Object{"filter": "sensitive_data_basic", "enforcement": "DISABLED"})
	}
	// Reject duplicate category observations instead of deciding which threshold wins.
	rows := arr(obj(f["raiSettings"])["raiFilters"])
	counts := map[string]int{}
	for _, r := range rows {
		counts[s(obj(r)["filterType"])]++
	}
	for _, r := range rows {
		cfg := obj(r)
		kind := s(cfg["filterType"])
		if counts[kind] != 1 {
			continue
		}
		switch kind {
		case "HATE_SPEECH", "HARASSMENT", "SEXUALLY_EXPLICIT", "DANGEROUS":
			if cfg["confidenceLevel"] == "HIGH" {
				observations = append(observations, inventory.Object{"filter": kind, "confidence_threshold": "HIGH"})
			}
		}
	}
	meta := obj(val(a, "templateMetadata"))
	if meta["enforcementType"] == "INSPECT_ONLY" {
		observations = append(observations, inventory.Object{"template_enforcement": "INSPECT_ONLY"})
	}
	if ignore, ok := meta["ignorePartialInvocationFailures"].(bool); ok && ignore {
		observations = append(observations, inventory.Object{"ignore_partial_invocation_failures": true})
	}
	if len(observations) == 0 {
		return nil
	}
	return result("info", "Model Armor template has explicit filter settings to review", "Confirm intended filter sensitivity, inspection/blocking integration and failure handling against the application's requirements; review inherited floor enforcement and actual template usage separately.", inventory.Object{"configured_observations": observations, "assessment": "Template configuration only; it may be unused. DISABLED refers only to the named selected filter. HIGH confidence reports only high-confidence matches and is less sensitive than lower thresholds, not a disabled filter; false-positive tradeoffs may be intentional. Basic Sensitive Data Protection configuration is distinct from advanced inspection/de-identification templates. Missing fields are unknown, not missing protection. Floor inheritance, exclusions, caller handling and effective app enforcement are not resolved. No unprotected or public AI endpoint, prompt leakage or successful bypass is established; no prompts, model responses, corpus or sanitization requests were accessed."})
}
