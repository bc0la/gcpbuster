package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func modelArmorExclusionConfiguration(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/ModelArmorTemplate" || !modelArmorTemplateName.MatchString(a.Name) {
		return nil
	}
	if raw, present := a.Resource.Data["projection_complete"]; present {
		if complete, ok := raw.(bool); !ok || !complete {
			return nil
		}
	}
	marker := obj(val(a, "_gcpbusterModelArmorExclusions"))
	if complete, ok := marker["complete"].(bool); !ok || !complete {
		return nil
	}
	enabled := map[string]bool{"PROMPT_INJECTION_AND_JAILBREAK": val(a, "filterConfig", "piAndJailbreakFilterSettings", "filterEnforcement") == "ENABLED"}
	rai := arr(val(a, "filterConfig", "raiSettings", "raiFilters"))
	raiValid := len(rai) > 0
	seenCategory := map[string]bool{}
	for _, r := range rai {
		kind := s(obj(r)["filterType"])
		if seenCategory[kind] {
			raiValid = false
		}
		seenCategory[kind] = true
		switch kind {
		case "HATE_SPEECH", "HARASSMENT", "DANGEROUS", "SEXUALLY_EXPLICIT":
		default:
			raiValid = false
		}
	}
	enabled["RESPONSIBLE_AI"] = raiValid
	var observations []any
	seen := map[[2]int]bool{}
	for _, r := range arr(marker["rules"]) {
		rule := obj(r)
		setIndex, sk := gatewaySecretInteger(rule["rule_set_index"])
		ruleIndex, rk := gatewaySecretInteger(rule["rule_index"])
		if !sk || !rk || setIndex < 0 || ruleIndex < 0 || setIndex > 4095 || ruleIndex > 4095 || rule["matching_scope"] != "MATCHING_SCOPE_PARTIAL_MATCH" {
			continue
		}
		catchAll, ok := rule["catch_all"].(bool)
		if !ok || !catchAll {
			continue
		}
		key := [2]int{setIndex, ruleIndex}
		if seen[key] {
			continue
		}
		seen[key] = true
		selected := []any{}
		valid := true
		seenFilter := map[string]bool{}
		filters, ok := rule["filter_types"].([]any)
		if !ok || len(filters) == 0 {
			continue
		}
		for _, f := range filters {
			kind, ok := f.(string)
			if !ok || (kind != "PROMPT_INJECTION_AND_JAILBREAK" && kind != "RESPONSIBLE_AI") || seenFilter[kind] {
				valid = false
				break
			}
			seenFilter[kind] = true
			if enabled[kind] {
				selected = append(selected, kind)
			}
		}
		if !valid || len(selected) == 0 {
			continue
		}
		observations = append(observations, inventory.Object{"rule_set_index": setIndex, "rule_index": ruleIndex, "enabled_filter_types": selected, "matching_scope": "MATCHING_SCOPE_PARTIAL_MATCH", "recognized_catch_all": true})
	}
	if len(observations) == 0 {
		return nil
	}
	return result("info", "Model Armor template configures catch-all exclusions for enabled filters", "Review whether these broad exceptions are intended and narrow them where appropriate. Verify actual template usage and independent floor enforcement without submitting prompts.", inventory.Object{"configured_exclusions": observations, "assessment": "Configuration-only match for a bounded exact catch-all regular-expression allowlist with explicit partial matching. For non-streaming sanitization these exclusions can override the entire selected prompt-injection/jailbreak or Responsible AI filter result, not just an individual text span. They do not disable Sensitive Data Protection, malicious-URI or floor-setting filters. Template usage, payload limits and runtime results remain unverified; arbitrary patterns, dictionaries and full-match behavior are not classified. Current Model Armor documentation provides exclusion override/skipped logging labels when sanitize-operation logging is enabled. No raw match strings, prompts, responses or token values are retained; no sanitization was invoked."})
}
