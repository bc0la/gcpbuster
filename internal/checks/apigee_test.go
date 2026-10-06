package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestApigeeAuthenticationPolicyValidatedEvidence(t *testing.T) {
	base := func() inventory.Object {
		return inventory.Object{"policy_digest": strings.Repeat("a", 64), "kind": "VerifyAPIKey", "disabled": true, "continue_on_error": false}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{{"policy_digest", "raw-name"}, {"kind", "AssignMessage"}, {"disabled", "true"}, {"disabled", false}, {"continue_on_error", nil}} {
		p := base()
		p[tc.key] = tc.value
		a := inventory.NewAsset("rev", "gcpbuster.googleapis.com/ApigeeProxyRevision", inventory.Object{"_gcpbusterApigeeAuth": inventory.Object{"complete": true, "auth_policies": []any{p}}})
		if got := apigeeAuthenticationPolicy(a, time.Now()); len(got) != 0 {
			t.Fatal(tc, got)
		}
	}
	a := inventory.NewAsset("rev", "gcpbuster.googleapis.com/ApigeeProxyRevision", inventory.Object{"_gcpbusterApigeeAuth": inventory.Object{"complete": true, "auth_policies": []any{base()}}})
	got := apigeeAuthenticationPolicy(a, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Evidence["assessment"].(string), "does not prove anonymous") {
		t.Fatal(got)
	}
	obj(a.Resource.Data["_gcpbusterApigeeAuth"])["complete"] = false
	if len(apigeeAuthenticationPolicy(a, time.Now())) != 0 {
		t.Fatal("incomplete")
	}
}

func TestApigeeFlowCalloutGraphScopeAndFlags(t *testing.T) {
	flowDigest := sha256.Sum256([]byte("flow"))
	endpoint := strings.Repeat("a", 64)
	policy := strings.Repeat("b", 64)
	for _, tc := range []struct {
		conditional, cont, enabled bool
		state, status, flow        string
		resolved, candidate        int
	}{
		{false, false, true, "READY", "resolved", "flow", 1, 1},
		{true, false, true, "READY", "resolved", "flow", 1, 0},
		{false, true, true, "READY", "resolved", "flow", 1, 0},
		{false, false, false, "READY", "disabled", "flow", 0, 0},
		{false, false, true, "PROGRESSING", "resolved", "flow", 1, 0},
		{false, false, true, "READY", "resolved", "other", 0, 0},
		{false, false, true, "READY", "ambiguous", "flow", 0, 0},
	} {
		ref := inventory.Object{"policy_digest": policy, "shared_flow_digest": hex.EncodeToString(flowDigest[:]), "conditional": tc.conditional, "enabled": tc.enabled, "continue_on_error": tc.cont}
		source := inventory.Object{"complete": true, "request_authentication": []any{inventory.Object{"endpoint_digest": endpoint, "endpoint_kind": "ProxyEndpoint", "literal_flow_callouts": []any{ref}}}}
		next := inventory.Object{"complete": true, "request_authentication": []any{inventory.Object{"endpoint_digest": strings.Repeat("c", 64), "endpoint_kind": "SharedFlow", "unconditional_authentication_steps": 1, "unresolved_flow_callouts": 0, "literal_flow_callouts": []any{}}}}
		edge := inventory.Object{"endpoint_digest": endpoint, "endpoint_kind": "ProxyEndpoint", "policy_digest": policy, "conditional": tc.conditional, "enabled": tc.enabled, "continue_on_error": tc.cont, "shared_flow": "organizations/demo/sharedflows/" + tc.flow, "status": tc.status, "revisions": []any{inventory.Object{"name": "organizations/demo/sharedflows/" + tc.flow + "/revisions/1", "state": tc.state, "auth": next}}}
		graph := inventory.Object{"complete": true, "edges": []any{edge}}
		got := apigeeCalloutGraphSummary(graph, source, "organizations/demo/sharedflows/", endpoint, true)
		if got["resolved_edges"] != tc.resolved || got["selected_verifier_candidates"] != tc.candidate {
			t.Fatal(tc, got)
		}
		if strings.Contains(fmt.Sprint(got), "organizations/") {
			t.Fatal("raw references leaked", got)
		}
		edge["shared_flow"] = "organizations/foreign/sharedflows/flow"
		if apigeeCalloutGraphSummary(graph, source, "organizations/demo/sharedflows/", endpoint, true)["resolved_edges"] != 0 {
			t.Fatal("foreign")
		}
	}
}

func TestApigeeFlowCalloutGraphCycleAndUnknown(t *testing.T) {
	flowDigest := sha256.Sum256([]byte("flow"))
	endpoint := strings.Repeat("a", 64)
	policy := strings.Repeat("b", 64)
	ref := inventory.Object{"policy_digest": policy, "shared_flow_digest": hex.EncodeToString(flowDigest[:]), "conditional": false, "enabled": true, "continue_on_error": false}
	auth := inventory.Object{"complete": true, "request_authentication": []any{inventory.Object{"endpoint_digest": endpoint, "endpoint_kind": "SharedFlow", "literal_flow_callouts": []any{ref}, "unconditional_authentication_steps": 0, "unresolved_flow_callouts": 1}}}
	edge := inventory.Object{"endpoint_digest": endpoint, "endpoint_kind": "SharedFlow", "policy_digest": policy, "conditional": false, "enabled": true, "continue_on_error": false, "shared_flow": "organizations/demo/sharedflows/flow", "status": "resolved"}
	graph := inventory.Object{"complete": true, "edges": []any{edge}}
	edge["revisions"] = []any{inventory.Object{"name": "organizations/demo/sharedflows/flow/revisions/1", "state": "READY", "auth": auth, "flow_callouts": graph}}
	got := apigeeCalloutGraphSummary(graph, auth, "organizations/demo/sharedflows/", endpoint, true)
	if got["resolved_edges"] != 1 || got["unknown_edges"].(int) < 2 || got["selected_verifier_candidates"] != 0 {
		t.Fatal(got)
	}
	edge["conditional"] = "false"
	if apigeeCalloutGraphSummary(graph, auth, "organizations/demo/sharedflows/", endpoint, true)["resolved_edges"] != 0 {
		t.Fatal("typed flags")
	}
}

func TestApigeeRequestAuthenticationConservativeEvidence(t *testing.T) {
	row := inventory.Object{"endpoint_digest": strings.Repeat("a", 64), "endpoint_kind": "ProxyEndpoint", "unconditional_authentication_steps": 0, "conditional_authentication_steps": 1, "non_enforcing_authentication_steps": 0, "unresolved_request_steps": 0}
	a := inventory.NewAsset("revision", inventory.ApigeeProxyRevisionType, inventory.Object{"_gcpbusterApigeeAuth": inventory.Object{"complete": true, "request_authentication": []any{row}}})
	got := apigeeRequestAuthentication(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" || !strings.Contains(got[0].Evidence["assessment"].(string), "not an anonymous-access") {
		t.Fatal(got)
	}
	for _, value := range []any{-1, "0", 0.5, nil, 1} {
		row["unconditional_authentication_steps"] = value
		if len(apigeeRequestAuthentication(a, time.Now())) != 0 {
			t.Fatal(value)
		}
	}
	row["unconditional_authentication_steps"] = float64(0)
	row["endpoint_kind"] = "SharedFlow"
	if len(apigeeRequestAuthentication(a, time.Now())) != 0 {
		t.Fatal("shared flow not proxy")
	}
	row["endpoint_kind"] = "ProxyEndpoint"
	obj(a.Resource.Data["_gcpbusterApigeeAuth"])["complete"] = false
	if len(apigeeRequestAuthentication(a, time.Now())) != 0 {
		t.Fatal("partial not complete")
	}
}

func TestApigeeInboundHookEvidenceUnknownNotAbsent(t *testing.T) {
	if apigeeInboundHookEvidence(nil)["status"] != "not_supplied" {
		t.Fatal("missing")
	}
	d := inventory.Object{"environments": []any{inventory.Object{"environment": "PRIVATE_ENV", "hooks": []any{inventory.Object{"point": "PreProxyFlowHook", "status": "present", "shared_flow": "PRIVATE_FLOW"}, inventory.Object{"point": "PostProxyFlowHook", "status": "absent"}}}}}
	got := apigeeInboundHookEvidence(d)
	if got["present"] != 1 || got["absent"] != 0 || got["unknown"] != 1 {
		t.Fatal(got)
	}
	if strings.Contains(fmt.Sprint(got), "PRIVATE") {
		t.Fatal(got)
	}
}

func TestApigeeDependencyExactScopeStateAndContinuation(t *testing.T) {
	for _, tc := range []struct {
		point, state string
		continuation any
		name         string
		candidate    bool
		assessment   string
	}{
		{"PreProxyFlowHook", "READY", false, "organizations/demo/sharedflows/s/revisions/1", true, "observed_native_configuration"},
		{"PreTargetFlowHook", "PROGRESSING", false, "organizations/demo/sharedflows/s/revisions/1", false, "observed_native_configuration"},
		{"PreProxyFlowHook", "READY", true, "organizations/demo/sharedflows/s/revisions/1", false, "observed_native_configuration"},
		{"PreProxyFlowHook", "READY", nil, "organizations/demo/sharedflows/s/revisions/1", false, "observed_native_configuration"},
		{"PostProxyFlowHook", "READY", false, "organizations/demo/sharedflows/s/revisions/1", false, "observed_native_configuration"},
		{"PreProxyFlowHook", "READY", false, "organizations/foreign/sharedflows/s/revisions/1", false, "unknown"},
	} {
		row := inventory.Object{"endpoint_digest": strings.Repeat("a", 64), "endpoint_kind": "SharedFlow", "unconditional_authentication_steps": 1, "conditional_authentication_steps": 0, "non_enforcing_authentication_steps": 0, "unresolved_request_steps": 1}
		hook := inventory.Object{"point": tc.point, "status": "present", "shared_flow": "organizations/demo/sharedflows/s", "complete": true, "continue_on_error": tc.continuation, "revisions": []any{inventory.Object{"name": tc.name, "state": tc.state, "auth": inventory.Object{"complete": true, "request_authentication": []any{row}}}}}
		a := inventory.NewAsset("//apigee.googleapis.com/organizations/demo/apis/api/revisions/1", inventory.ApigeeProxyRevisionType, inventory.Object{"deployments": []any{inventory.Object{"environment": "PRIVATE_ENV"}}, "_gcpbusterApigeeDependencies": inventory.Object{"environments": []any{inventory.Object{"environment": "PRIVATE_ENV", "hooks": []any{hook}}}}})
		got := apigeeDependencyContexts(a)
		var matched inventory.Object
		for _, v := range arr(obj(got[0])["hooks"]) {
			h := obj(v)
			if h["point"] == tc.point {
				matched = h
			}
		}
		if matched["revision_assessment"] != tc.assessment || (matched["request_enforcement_candidate"] == true) != tc.candidate {
			t.Fatal(tc, matched)
		}
		if strings.Contains(fmt.Sprint(got), "PRIVATE_ENV") {
			t.Fatal(got)
		}
		a.Resource.Data["deployments"] = []any{inventory.Object{"environment": "other"}}
		if obj(apigeeDependencyContexts(a)[0])["status"] != "unknown_environment_scope" {
			t.Fatal("foreign env")
		}
	}
}
