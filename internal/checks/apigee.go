package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"math"
	"regexp"
	"strings"
	"time"
)

var apigeePolicyDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func apigeeAuthenticationPolicy(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/ApigeeProxyRevision" {
		return nil
	}
	d := obj(val(a, "_gcpbusterApigeeAuth"))
	complete, ok := d["complete"].(bool)
	if !ok || !complete {
		return nil
	}
	var out []Result
	seen := map[string]bool{}
	for _, raw := range arr(d["auth_policies"]) {
		p := obj(raw)
		digest := s(p["policy_digest"])
		kind := s(p["kind"])
		disabled, dok := p["disabled"].(bool)
		cont, cok := p["continue_on_error"].(bool)
		if !apigeePolicyDigest.MatchString(digest) || seen[digest] || (kind != "VerifyAPIKey" && kind != "VerifyJWT" && kind != "OAuthV2") || !dok || !cok || (!disabled && !cont) {
			continue
		}
		seen[digest] = true
		out = append(out, result("medium", "Attached Apigee authentication policy is disabled or continues after errors", "Review whether the attached policy should enforce authentication and stop failed requests. Review all flow conditions, fault handlers and independent authorization before concluding any route is anonymous.", inventory.Object{"policy_digest": digest, "policy_kind": kind, "disabled": disabled, "continue_on_error": cont, "assessment": "Selected revision bundle configuration only; policy is referenced by a Step in a parsed endpoint or shared flow. OAuthV2 is restricted to VerifyAccessToken. Attachment can be conditional or response/fault-only; other policies, shared flows, flow hooks, ingress and backend authentication can still enforce access. This does not prove anonymous routes, active deployment or successful invocation. No API target was called; policy names, source, URLs and credential values were not retained."})...)
	}
	return out
}

func apigeeRequestAuthentication(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.ApigeeProxyRevisionType {
		return nil
	}
	d := obj(val(a, "_gcpbusterApigeeAuth"))
	if complete, ok := d["complete"].(bool); !ok || !complete {
		return nil
	}
	var out []Result
	seen := map[string]bool{}
	for _, raw := range arr(d["request_authentication"]) {
		row := obj(raw)
		digest := s(row["endpoint_digest"])
		if !apigeePolicyDigest.MatchString(digest) || seen[digest] || s(row["endpoint_kind"]) != "ProxyEndpoint" {
			continue
		}
		counts := inventory.Object{}
		valid := true
		for _, key := range []string{"unconditional_authentication_steps", "conditional_authentication_steps", "non_enforcing_authentication_steps", "unresolved_request_steps"} {
			n, ok := apigeeStepCount(row[key])
			if !ok {
				valid = false
				break
			}
			counts[key] = n
		}
		if !valid || counts["unconditional_authentication_steps"].(int) != 0 {
			continue
		}
		seen[digest] = true
		counts["endpoint_digest"] = digest
		counts["configured_base_path"] = apigeeBasePathEvidence(row["configured_base_path"])
		counts["scope"] = "native_proxy_inbound_request_configuration"
		counts["environment_dependencies"] = apigeeDependencyContexts(a)
		counts["static_flow_callout_dependencies"] = apigeeFlowCalloutContexts(a, digest)
		counts["dependency_assessment"] = "Flow hooks, shared-flow dependencies, custom policies and backend authentication remain separate; this native request-flow summary does not establish their absence or effectiveness."
		counts["assessment"] = "No unconditional enforcing VerifyAPIKey, VerifyJWT or OAuthV2 VerifyAccessToken Step was identified in this proxy endpoint's native request PreFlow/PostFlow. Conditional Flow and Step applicability is unresolved; response/fault-only policies are not counted as inbound enforcement. Other policies, flow hooks, shared flows, custom code or backend controls may still authenticate requests. This is not an anonymous-access or effective reachability finding, and no target was invoked."
		out = append(out, result("info", "Apigee native request flow needs authentication review", "Review native request-flow conditions and independent enforcement, including environment hooks and referenced shared flows; do not infer public access from the absence of these selected policy types.", counts)...)
	}
	return out
}

// Graph reads are collector-bounded; these independent bounds also protect
// evaluation of supplied offline evidence. Counts never imply effective auth.
func apigeeFlowCalloutContexts(a inventory.Asset, endpointDigest string) []any {
	match := apigeeObservedRevision.FindStringSubmatch(a.Name)
	if len(match) != 2 {
		return []any{inventory.Object{"status": "unknown_scope"}}
	}
	parent := "organizations/" + match[1] + "/sharedflows/"
	deployed := map[string]bool{}
	for _, v := range arr(a.Resource.Data["deployments"]) {
		env := s(obj(v)["environment"])
		if apigeeObservedID.MatchString(env) {
			deployed[env] = true
		}
	}
	rows := arr(obj(a.Resource.Data["_gcpbusterApigeeFlowCallouts"])["environments"])
	if len(rows) == 0 {
		return []any{inventory.Object{"status": "not_supplied"}}
	}
	seen := map[string]bool{}
	var out []any
	for _, v := range rows {
		graph := obj(v)
		env := s(graph["environment"])
		if !deployed[env] || seen[env] {
			out = append(out, inventory.Object{"status": "unknown_environment_scope"})
			continue
		}
		seen[env] = true
		digest := sha256.Sum256([]byte(env))
		summary := apigeeCalloutGraphSummary(graph, obj(a.Resource.Data["_gcpbusterApigeeAuth"]), parent, endpointDigest, true)
		summary["environment_digest"] = hex.EncodeToString(digest[:])
		out = append(out, summary)
	}
	return out
}

func apigeeCalloutGraphSummary(graph, source inventory.Object, parent, endpointDigest string, chainEligible bool) inventory.Object {
	counts := inventory.Object{"status": "observed_static_configuration_only", "resolved_edges": 0, "disabled_edges": 0, "conditional_edges": 0, "nonblocking_edges": 0, "unknown_edges": 0, "selected_verifier_candidates": 0}
	inc := func(key string) { counts[key] = counts[key].(int) + 1 }
	remaining := 64
	var visit func(inventory.Object, inventory.Object, string, bool, int, map[string]bool)
	visit = func(g, auth inventory.Object, endpoint string, eligible bool, depth int, ancestors map[string]bool) {
		if depth > 8 || remaining <= 0 {
			inc("unknown_edges")
			return
		}
		if flag, ok := auth["complete"].(bool); !ok || !flag {
			inc("unknown_edges")
			return
		}
		if complete, ok := g["complete"].(bool); !ok || !complete {
			inc("unknown_edges")
		}
		edges, ok := g["edges"].([]any)
		if !ok {
			inc("unknown_edges")
			return
		}
		for _, v := range edges {
			if remaining <= 0 {
				inc("unknown_edges")
				return
			}
			remaining--
			e := obj(v)
			ed := s(e["endpoint_digest"])
			pd := s(e["policy_digest"])
			kind := s(e["endpoint_kind"])
			if endpoint != "" && ed != endpoint {
				continue
			}
			conditional, cok := e["conditional"].(bool)
			enabled, eok := e["enabled"].(bool)
			cont, ok := e["continue_on_error"].(bool)
			if !cok || !eok || !ok || !apigeePolicyDigest.MatchString(ed) || !apigeePolicyDigest.MatchString(pd) || (kind != "ProxyEndpoint" && kind != "SharedFlow") {
				inc("unknown_edges")
				continue
			}
			matched := false
			flowDigest := sha256.Sum256([]byte(strings.TrimPrefix(s(e["shared_flow"]), parent)))
			for _, r := range arr(auth["request_authentication"]) {
				row := obj(r)
				if row["endpoint_digest"] != ed || row["endpoint_kind"] != kind {
					continue
				}
				for _, ref := range arr(row["literal_flow_callouts"]) {
					rr := obj(ref)
					if rr["policy_digest"] == pd && rr["shared_flow_digest"] == hex.EncodeToString(flowDigest[:]) && rr["conditional"] == conditional && rr["enabled"] == enabled && rr["continue_on_error"] == cont {
						matched = true
					}
				}
			}
			if !matched {
				inc("unknown_edges")
				continue
			}
			if conditional {
				inc("conditional_edges")
			}
			if cont {
				inc("nonblocking_edges")
			}
			flow := s(e["shared_flow"])
			if !strings.HasPrefix(flow, parent) || !apigeeObservedID.MatchString(strings.TrimPrefix(flow, parent)) {
				inc("unknown_edges")
				continue
			}
			if !enabled && e["status"] == "disabled" {
				inc("disabled_edges")
				continue
			}
			if !enabled || e["status"] != "resolved" {
				inc("unknown_edges")
				continue
			}
			revisions := arr(e["revisions"])
			if len(revisions) != 1 {
				inc("unknown_edges")
				continue
			}
			rev := obj(revisions[0])
			name := s(rev["name"])
			if !strings.HasPrefix(name, flow+"/revisions/") || !apigeeObservedNumber.MatchString(strings.TrimPrefix(name, flow+"/revisions/")) || ancestors[name] {
				inc("unknown_edges")
				continue
			}
			nextAuth := obj(rev["auth"])
			if complete, ok := nextAuth["complete"].(bool); !ok || !complete {
				inc("unknown_edges")
				continue
			}
			request := arr(nextAuth["request_authentication"])
			if len(request) != 1 || obj(request[0])["endpoint_kind"] != "SharedFlow" {
				inc("unknown_edges")
				continue
			}
			inc("resolved_edges")
			state := s(rev["state"])
			nextEligible := eligible && !conditional && !cont && state == "READY"
			if state != "READY" {
				inc("unknown_edges")
			}
			row := obj(request[0])
			n, nok := apigeeStepCount(row["unconditional_authentication_steps"])
			if !nok {
				inc("unknown_edges")
			} else if nextEligible && n > 0 {
				inc("selected_verifier_candidates")
			}
			if n, ok := apigeeStepCount(row["unresolved_flow_callouts"]); ok && n > 0 {
				inc("unknown_edges")
			}
			if len(arr(row["literal_flow_callouts"])) > 0 {
				next := map[string]bool{}
				for k, v := range ancestors {
					next[k] = v
				}
				next[name] = true
				visit(obj(rev["flow_callouts"]), nextAuth, "", nextEligible, depth+1, next)
			}
		}
	}
	visit(graph, source, endpointDigest, chainEligible, 0, map[string]bool{})
	counts["assessment"] = "Validated static literal request FlowCallout observations only. Conditions, disabled/nonblocking steps, non-READY or unknown revisions and unresolved graph branches do not establish request enforcement. Selected verifier candidates are not effective authentication, runtime deployment or anonymous-access conclusions."
	return counts
}

var apigeeObservedRevision = regexp.MustCompile(`^//apigee\.googleapis\.com/organizations/([A-Za-z0-9_-]+)/apis/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/revisions/[1-9][0-9]{0,18}$`)
var apigeeObservedID = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`)
var apigeeObservedNumber = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func apigeeDependencyContexts(a inventory.Asset) []any {
	match := apigeeObservedRevision.FindStringSubmatch(a.Name)
	if len(match) != 2 {
		return []any{inventory.Object{"status": "unknown_scope"}}
	}
	parent := "organizations/" + match[1] + "/sharedflows/"
	deployed := map[string]bool{}
	for _, raw := range arr(a.Resource.Data["deployments"]) {
		env := s(obj(raw)["environment"])
		if apigeeObservedID.MatchString(env) {
			deployed[env] = true
		}
	}
	rows, ok := obj(a.Resource.Data["_gcpbusterApigeeDependencies"])["environments"].([]any)
	if !ok || len(rows) == 0 {
		return []any{inventory.Object{"status": "not_supplied"}}
	}
	seenEnv := map[string]bool{}
	var out []any
	for _, raw := range rows {
		env := s(obj(raw)["environment"])
		if !deployed[env] || seenEnv[env] {
			out = append(out, inventory.Object{"status": "unknown_environment_scope"})
			continue
		}
		seenEnv[env] = true
		digest := sha256.Sum256([]byte(env))
		context := inventory.Object{"environment_digest": hex.EncodeToString(digest[:]), "status": "observed_configuration_only"}
		hooks := arr(obj(raw)["hooks"])
		selected := map[string]inventory.Object{}
		duplicates := map[string]bool{}
		for _, v := range hooks {
			h := obj(v)
			point := s(h["point"])
			if selected[point] != nil {
				duplicates[point] = true
			}
			selected[point] = h
		}
		var summaries []any
		for _, point := range []string{"PreProxyFlowHook", "PreTargetFlowHook", "PostTargetFlowHook", "PostProxyFlowHook"} {
			h := selected[point]
			phase := "request"
			if strings.HasPrefix(point, "Post") {
				phase = "response"
			}
			row := inventory.Object{"point": point, "phase": phase, "status": "unknown"}
			summaries = append(summaries, row)
			if h == nil || duplicates[point] {
				continue
			}
			if flag, ok := h["continue_on_error"].(bool); ok {
				row["continue_on_error"] = flag
			} else {
				row["continuation_status"] = "unknown"
			}
			if h["status"] == "absent" {
				if _, exists := h["shared_flow"]; !exists {
					row["status"] = "absent"
				}
				continue
			}
			if h["status"] != "present" {
				continue
			}
			flow := s(h["shared_flow"])
			id := strings.TrimPrefix(flow, parent)
			if !strings.HasPrefix(flow, parent) || !apigeeObservedID.MatchString(id) {
				continue
			}
			row["status"] = "present"
			row["revision_assessment"] = "unknown"
			complete, ok := h["complete"].(bool)
			revisions := arr(h["revisions"])
			if !ok || !complete || len(revisions) != 1 {
				continue
			}
			rev := obj(revisions[0])
			revisionName := s(rev["name"])
			if !strings.HasPrefix(revisionName, flow+"/revisions/") || !apigeeObservedNumber.MatchString(strings.TrimPrefix(revisionName, flow+"/revisions/")) {
				continue
			}
			state := s(rev["state"])
			switch state {
			case "READY", "PROGRESSING", "ERROR", "RUNTIME_STATE_UNSPECIFIED":
				row["observed_revision_state"] = state
			default:
				row["observed_revision_state"] = "unknown"
			}
			auth := obj(rev["auth"])
			if flag, ok := auth["complete"].(bool); !ok || !flag {
				continue
			}
			request := arr(auth["request_authentication"])
			if len(request) != 1 {
				continue
			}
			summary := obj(request[0])
			if summary["endpoint_kind"] != "SharedFlow" || !apigeePolicyDigest.MatchString(s(summary["endpoint_digest"])) {
				continue
			}
			counts := inventory.Object{}
			valid := true
			for _, key := range []string{"unconditional_authentication_steps", "conditional_authentication_steps", "non_enforcing_authentication_steps", "unresolved_request_steps"} {
				n, ok := apigeeStepCount(summary[key])
				if !ok {
					valid = false
					break
				}
				counts[key] = n
			}
			if !valid {
				continue
			}
			row["selected_native_steps"] = counts
			row["revision_assessment"] = "observed_native_configuration"
			flag, known := h["continue_on_error"].(bool)
			row["request_enforcement_candidate"] = phase == "request" && state == "READY" && known && !flag && counts["unconditional_authentication_steps"].(int) > 0
			if len(arr(summary["literal_flow_callouts"])) > 0 {
				row["static_flow_callout_dependencies"] = apigeeCalloutGraphSummary(obj(rev["flow_callouts"]), auth, parent, "", phase == "request" && state == "READY" && known && !flag)
			}
			row["assessment"] = "Exact observed same-environment revision metadata only; candidate is not an effective authentication decision. Nested FlowCallout/custom policy, conditions and runtime controls remain unresolved."
		}
		context["hooks"] = summaries
		out = append(out, context)
	}
	return out
}

// Summarize observed dependencies without promoting a present/absent hook to
// an effective authentication decision or copying names/configuration text.
func apigeeInboundHookEvidence(d inventory.Object) inventory.Object {
	if d == nil {
		return inventory.Object{"status": "not_supplied"}
	}
	present, absent, unknown := 0, 0, 0
	environments, ok := d["environments"].([]any)
	if !ok || len(environments) == 0 {
		return inventory.Object{"status": "unknown"}
	}
	for _, raw := range environments {
		hooks, ok := obj(raw)["hooks"].([]any)
		if !ok {
			unknown++
			continue
		}
		seen := map[string]bool{}
		for _, rawHook := range hooks {
			h := obj(rawHook)
			point := s(h["point"])
			if point != "PreProxyFlowHook" && point != "PreTargetFlowHook" {
				continue
			}
			if seen[point] {
				unknown++
				continue
			}
			seen[point] = true
			switch s(h["status"]) {
			case "present":
				present++
			case "absent":
				absent++
			default:
				unknown++
			}
		}
		for _, point := range []string{"PreProxyFlowHook", "PreTargetFlowHook"} {
			if !seen[point] {
				unknown++
			}
		}
	}
	return inventory.Object{"status": "observed_configuration_only", "present": present, "absent": absent, "unknown": unknown}
}

func apigeeStepCount(raw any) (int, bool) {
	switch n := raw.(type) {
	case int:
		return n, n >= 0 && n <= 100000
	case float64:
		if n >= 0 && n <= 100000 && math.Trunc(n) == n {
			return int(n), true
		}
	}
	return 0, false
}
