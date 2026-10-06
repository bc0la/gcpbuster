package inventory

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func apigeeTestBundle(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		f, err := w.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestApigeeLiteralRequestConditionsAndCalloutPropagation(t *testing.T) {
	for _, tc := range []struct {
		condition                        string
		unconditional, conditional, refs int
	}{
		{"true", 1, 0, 1}, {" ( ( true ) ) ", 1, 0, 1}, {"false", 0, 0, 0}, {"((false))", 0, 0, 0},
		{"request.header.test = true", 0, 1, 1}, {"true or false", 0, 1, 1}, {"TRUE", 0, 1, 1}, {"'true'", 0, 1, 1}, {"(true))", 0, 1, 1},
	} {
		endpoint := `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name><Condition>` + tc.condition + `</Condition></Step><Step><Name>call</Name><Condition>` + tc.condition + `</Condition></Step></Request></PreFlow></ProxyEndpoint>`
		got, refs, err := projectApigeeBundleWithReferences(apigeeTestBundle(t, [][2]string{
			{"apiproxy/proxies/default.xml", endpoint}, {"apiproxy/policies/auth.xml", `<VerifyJWT name="auth"/>`}, {"apiproxy/policies/call.xml", `<FlowCallout name="call"><SharedFlowBundle>shared</SharedFlowBundle></FlowCallout>`},
		}))
		if err != nil {
			t.Fatal(tc, err)
		}
		r := Obj(List(got["request_authentication"])[0])
		if r["unconditional_authentication_steps"] != tc.unconditional || r["conditional_authentication_steps"] != tc.conditional || len(refs) != tc.refs {
			t.Fatal(tc, got, refs)
		}
		if len(refs) > 0 && refs[0].Conditional != (tc.conditional > 0) {
			t.Fatal(tc, refs)
		}
	}
	// First-match conditional Flow remains conditional even with literal true;
	// false Flow suppresses its true child, and response-only never enters graph.
	for _, condition := range []string{"true", "false"} {
		got, refs, err := projectApigeeBundleWithReferences(apigeeTestBundle(t, [][2]string{
			{"apiproxy/proxies/default.xml", `<ProxyEndpoint><Flows><Flow><Condition>` + condition + `</Condition><Request><Step><Name>call</Name><Condition>true</Condition></Step></Request></Flow></Flows><PostFlow><Response><Step><Name>call</Name><Condition>true</Condition></Step></Response></PostFlow></ProxyEndpoint>`},
			{"apiproxy/policies/call.xml", `<FlowCallout name="call"><SharedFlowBundle>shared</SharedFlowBundle></FlowCallout>`},
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if condition == "true" {
			want = 1
		}
		if len(refs) != want || (want == 1 && !refs[0].Conditional) {
			t.Fatal(condition, got, refs)
		}
	}
}

func TestApigeeLiteralConditionsBoundsAndMalformed(t *testing.T) {
	for _, raw := range []string{strings.Repeat("(", 33) + "true" + strings.Repeat(")", 33), strings.Repeat(" ", 257) + "false", "(false) or (true)", "!false", "\"false\""} {
		if _, known := apigeeLiteralCondition(raw); known {
			t.Fatal(raw)
		}
	}
	for _, condition := range []string{`<Condition ref="true">true</Condition>`, `<Condition>false</Condition><Condition>true</Condition>`, `<Condition><Value>false</Value></Condition>`} {
		_, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/default.xml", `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name>` + condition + `</Step></Request></PreFlow></ProxyEndpoint>`}, {"apiproxy/policies/auth.xml", `<VerifyJWT name="auth"/>`}}))
		if err == nil {
			t.Fatal(condition)
		}
	}
}

func TestApigeeBundleLinkedAuthenticationProjection(t *testing.T) {
	for _, policy := range []string{`<VerifyAPIKey name="PRIVATE_POLICY" enabled="false"><APIKey ref="PRIVATE_HEADER"/></VerifyAPIKey>`, `<VerifyJWT name="PRIVATE_POLICY" continueOnError="true"/>`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><OAuthV2 name="PRIVATE_POLICY" enabled="false"><Operation>VerifyAccessToken</Operation></OAuthV2>`} {
		bundle := apigeeTestBundle(t, [][2]string{{"apiproxy/policies/auth.xml", policy}, {"apiproxy/proxies/default.xml", `<ProxyEndpoint name="default"><PreFlow><Request><Step><Name>PRIVATE_POLICY</Name><Condition>request.header.private = "x"</Condition></Step></Request></PreFlow></ProxyEndpoint>`}})
		got, err := projectApigeeBundle(bundle)
		if err != nil || got["complete"] != true || len(List(got["auth_policies"])) != 1 {
			t.Fatal(got, err)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "header") {
			t.Fatal(string(b))
		}
	}
}

func TestApigeeBundleUnattachedAndNonVerification(t *testing.T) {
	for _, policy := range []string{`<VerifyAPIKey name="auth"/>`, `<OAuthV2 name="auth" enabled="false"><Operation>GenerateAccessToken</Operation></OAuthV2>`} {
		got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/policies/auth.xml", policy}, {"apiproxy/proxies/default.xml", `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow></ProxyEndpoint>`}}))
		if err != nil || len(List(got["auth_policies"])) != 0 {
			t.Fatal(got, err)
		}
	}
	got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/policies/auth.xml", `<VerifyAPIKey name="auth" enabled="false"/>`}}))
	if err != nil || len(List(got["auth_policies"])) != 0 {
		t.Fatal("unattached", got, err)
	}
}

func TestApigeeBundleRejectsUnsafeAndAmbiguous(t *testing.T) {
	policy := [2]string{"apiproxy/policies/auth.xml", `<VerifyAPIKey name="auth" enabled="false"/>`}
	endpoint := [2]string{"apiproxy/proxies/default.xml", `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow></ProxyEndpoint>`}
	for _, extra := range [][2]string{
		{"../evil.xml", "x"}, {"apiproxy/../evil.xml", "x"}, {"..", "x"}, {"C:/evil.xml", "x"}, {"/evil.xml", "x"}, policy,
		{"apiproxy/policies/duplicate.xml", policy[1]},
		{"apiproxy/proxies/bad.xml", `<!DOCTYPE ProxyEndpoint [<!ENTITY x SYSTEM "https://evil.test">]><ProxyEndpoint/>`},
		{"apiproxy/proxies/bad.xml", `<?fetch https://evil.test?><ProxyEndpoint/>`},
		{"apiproxy/proxies/bad.xml", `<ProxyEndpoint xmlns="evil"/>`},
		{"apiproxy/proxies/bad.xml", `<ProxyEndpoint><Properties><Step><Name>auth</Name></Step></Properties></ProxyEndpoint>`},
		{"apiproxy/proxies/bad.xml", `<ProxyEndpoint><PreFlow><Request><Step><Name>missing</Name></Step></Request></PreFlow></ProxyEndpoint>`},
		{"apiproxy/proxies/bad.xml", `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name><Unexpected/></Step></Request></PreFlow></ProxyEndpoint>`},
		{"resources/oversized", strings.Repeat("x", (4<<20)+1)},
	} {
		got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{policy, endpoint, extra}))
		if err == nil || got["complete"] != false || len(List(got["auth_policies"])) != 0 {
			t.Fatal(extra[0], got, err)
		}
	}
	if got, err := projectApigeeBundle([]byte("not zip")); err == nil || got["complete"] != false {
		t.Fatal(got, err)
	}
}

func TestApigeeXMLStrictAttributesAndSharedFlow(t *testing.T) {
	for _, raw := range []string{`<VerifyAPIKey name="a" enabled="false" enabled="true"/>`, `<VerifyAPIKey name="a"/><VerifyAPIKey name="b"/>`, `<VerifyAPIKey name="a">&unknown;</VerifyAPIKey>`} {
		if _, err := parseApigeeXML([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"sharedflowbundle/policies/auth.xml", `<VerifyJWT name="auth" continueOnError="true"/>`}, {"sharedflowbundle/sharedflows/default.xml", `<SharedFlow><Step><Name>auth</Name></Step></SharedFlow>`}}))
	if err != nil || len(List(got["auth_policies"])) != 1 {
		t.Fatal(got, err)
	}
}

func TestApigeeBundleAggregateXMLTokenBound(t *testing.T) {
	entries := [][2]string{}
	// Each document is individually below100k tokens and4MiB, while their
	// retained trees together exceed the250k-token aggregate ceiling.
	for _, name := range []string{"one", "two", "three"} {
		entries = append(entries, [2]string{"apiproxy/policies/" + name + ".xml", `<AssignMessage name="` + name + `">` + strings.Repeat("<Item/>", 45000) + `</AssignMessage>`})
	}
	got, err := projectApigeeBundle(apigeeTestBundle(t, entries))
	if err == nil || got["complete"] != false || len(List(got["auth_policies"])) != 0 {
		t.Fatal(got, err)
	}
}

func TestApigeeRequestFlowAuthenticationContexts(t *testing.T) {
	for _, tc := range []struct {
		flow, policy                                         string
		unconditional, conditional, nonEnforcing, unresolved int
	}{
		{`<PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow>`, `<VerifyJWT name="auth"/>`, 1, 0, 0, 0},
		{`<PostFlow><Request><Step><Name>auth</Name></Step></Request></PostFlow>`, `<VerifyAPIKey name="auth"/>`, 1, 0, 0, 0},
		{`<PreFlow><Request><Step><Name>auth</Name><Condition>private_expression</Condition></Step></Request></PreFlow>`, `<VerifyJWT name="auth"/>`, 0, 1, 0, 0},
		{`<Flows><Flow><Request><Step><Name>auth</Name></Step></Request></Flow></Flows>`, `<VerifyJWT name="auth"/>`, 0, 1, 0, 0},
		{`<PreFlow><Response><Step><Name>auth</Name></Step></Response></PreFlow>`, `<VerifyJWT name="auth"/>`, 0, 0, 0, 0},
		{`<DefaultFaultRule><Step><Name>auth</Name></Step></DefaultFaultRule>`, `<VerifyJWT name="auth"/>`, 0, 0, 0, 0},
		{`<PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow>`, `<OAuthV2 name="auth"><Operation>GenerateAccessToken</Operation></OAuthV2>`, 0, 0, 0, 1},
		{`<PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow>`, `<VerifyJWT name="auth" continueOnError="true"/>`, 0, 0, 1, 0},
		{`<PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow>`, `<FlowCallout name="auth"><SharedFlowBundle>private_flow</SharedFlowBundle></FlowCallout>`, 0, 0, 0, 1},
	} {
		got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/policies/auth.xml", tc.policy}, {"apiproxy/proxies/private_endpoint.xml", `<ProxyEndpoint>` + tc.flow + `</ProxyEndpoint>`}}))
		if err != nil {
			t.Fatal(err)
		}
		rows := List(got["request_authentication"])
		if len(rows) != 1 {
			t.Fatal(got)
		}
		r := Obj(rows[0])
		if r["unconditional_authentication_steps"] != tc.unconditional || r["conditional_authentication_steps"] != tc.conditional || r["non_enforcing_authentication_steps"] != tc.nonEnforcing || r["unresolved_request_steps"] != tc.unresolved {
			t.Fatal(tc, r)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "private_") {
			t.Fatal(string(encoded))
		}
	}
}

func TestApigeeRequestFlowAmbiguityAndSharedFlow(t *testing.T) {
	for _, xml := range []string{`<ProxyEndpoint><PreFlow/><PreFlow/></ProxyEndpoint>`, `<ProxyEndpoint><PreFlow><Request/><Request/></PreFlow></ProxyEndpoint>`, `<ProxyEndpoint><PreFlow><Request><Step><Name>auth</Name><Condition>a</Condition><Condition>b</Condition></Step></Request></PreFlow></ProxyEndpoint>`} {
		got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/main.xml", xml}, {"apiproxy/policies/auth.xml", `<VerifyJWT name="auth"/>`}}))
		if err == nil || got["complete"] != false {
			t.Fatal(got, err)
		}
	}
	got, err := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"sharedflowbundle/sharedflows/main.xml", `<SharedFlow><Step><Name>auth</Name></Step></SharedFlow>`}, {"sharedflowbundle/policies/auth.xml", `<VerifyJWT name="auth"/>`}}))
	if err != nil || Obj(List(got["request_authentication"])[0])["unconditional_authentication_steps"] != 1 {
		t.Fatal(got, err)
	}
}

func TestApigeeFlowCalloutTransientReferences(t *testing.T) {
	for _, tc := range []struct {
		flow, policy               string
		refs, unresolved           int
		conditional, enabled, cont bool
	}{
		{`<PreFlow><Request><Step><Name>PRIVATE_POLICY</Name></Step></Request></PreFlow>`, `<FlowCallout name="PRIVATE_POLICY"><SharedFlowBundle>PRIVATE_FLOW</SharedFlowBundle></FlowCallout>`, 1, 0, false, true, false},
		{`<Flows><Flow><Request><Step><Name>PRIVATE_POLICY</Name></Step></Request></Flow></Flows>`, `<FlowCallout name="PRIVATE_POLICY" enabled="false" continueOnError="true"><SharedFlowBundle>PRIVATE_FLOW</SharedFlowBundle></FlowCallout>`, 1, 0, true, false, true},
		{`<PreFlow><Response><Step><Name>PRIVATE_POLICY</Name></Step></Response></PreFlow>`, `<FlowCallout name="PRIVATE_POLICY"><SharedFlowBundle>PRIVATE_FLOW</SharedFlowBundle></FlowCallout>`, 0, 0, false, false, false},
		{`<DefaultFaultRule><Step><Name>PRIVATE_POLICY</Name></Step></DefaultFaultRule>`, `<FlowCallout name="PRIVATE_POLICY"><SharedFlowBundle>PRIVATE_FLOW</SharedFlowBundle></FlowCallout>`, 0, 0, false, false, false},
		{`<PreFlow><Request><Step><Name>PRIVATE_POLICY</Name></Step></Request></PreFlow>`, `<FlowCallout name="PRIVATE_POLICY"><SharedFlowBundle>{dynamic}</SharedFlowBundle></FlowCallout>`, 0, 1, false, false, false},
		{`<PreFlow><Request><Step><Name>PRIVATE_POLICY</Name></Step></Request></PreFlow>`, `<FlowCallout name="PRIVATE_POLICY"><SharedFlowBundle ref="PRIVATE_VARIABLE">PRIVATE_FLOW</SharedFlowBundle></FlowCallout>`, 0, 1, false, false, false},
	} {
		got, refs, err := projectApigeeBundleWithReferences(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/private_endpoint.xml", `<ProxyEndpoint>` + tc.flow + `</ProxyEndpoint>`}, {"apiproxy/policies/call.xml", tc.policy}}))
		if err != nil || len(refs) != tc.refs {
			t.Fatal(tc, got, refs, err)
		}
		if tc.refs > 0 && (refs[0].SharedFlow != "PRIVATE_FLOW" || refs[0].Conditional != tc.conditional || refs[0].Enabled != tc.enabled || refs[0].ContinueOnError != tc.cont) {
			t.Fatal(refs)
		}
		row := Obj(List(got["request_authentication"])[0])
		if row["unresolved_flow_callouts"] != tc.unresolved {
			t.Fatal(got)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "private_endpoint") || strings.Contains(string(encoded), "dynamic") {
			t.Fatal(string(encoded))
		}
	}
}

func TestApigeeFlowCalloutMalformedAndUnattached(t *testing.T) {
	for _, policy := range []string{`<FlowCallout name="call"/>`, `<FlowCallout name="call"><SharedFlowBundle>a</SharedFlowBundle><SharedFlowBundle>b</SharedFlowBundle></FlowCallout>`, `<FlowCallout name="call" enabled="invalid"><SharedFlowBundle>a</SharedFlowBundle></FlowCallout>`, `<FlowCallout name="call"><SharedFlowBundle><Nested/></SharedFlowBundle></FlowCallout>`} {
		got, refs, err := projectApigeeBundleWithReferences(apigeeTestBundle(t, [][2]string{{"sharedflowbundle/sharedflows/main.xml", `<SharedFlow><Step><Name>call</Name></Step></SharedFlow>`}, {"sharedflowbundle/policies/call.xml", policy}}))
		if err == nil || len(refs) != 0 || got["complete"] != false {
			t.Fatal(got, refs, err)
		}
	}
	got, refs, err := projectApigeeBundleWithReferences(apigeeTestBundle(t, [][2]string{{"apiproxy/policies/call.xml", `<FlowCallout name="call"><SharedFlowBundle>private_flow</SharedFlowBundle></FlowCallout>`}}))
	if err != nil || len(refs) != 0 || got["complete"] != true {
		t.Fatal(got, refs, err)
	}
}
