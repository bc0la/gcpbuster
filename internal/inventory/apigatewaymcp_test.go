package inventory

import (
	"encoding/json"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func mcpRoot(t *testing.T, body string) map[string]*yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	root, ok := apiGatewayAuthMap(doc.Content[0])
	if !ok {
		t.Fatal(body)
	}
	return root
}

func TestAPIGatewayMCPEnablementAndOptOut(t *testing.T) {
	for _, tc := range []struct {
		body            string
		enabled, global bool
		ins, outs       int
	}{
		{`{"openapi":"3.0.3","paths":{}}`, false, false, 0, 0},
		{`{"openapi":"3.0.3","x-google-api-management":{"mcp":true},"paths":{}}`, true, true, 0, 0},
		{`{"openapi":"3.0.3","x-google-api-management":{"mcp":{}},"paths":{"/secret":{"get":{"x-google-mcp-tool":false}}}}`, true, true, 0, 1},
		{`{"openapi":"3.0.3","x-google-api-management":{"mcp":false,"backends":{"default":{"address":"https://example.invalid"}}},"x-google-backend":"default","paths":{"/secret":{"post":{"x-google-mcp-tool":{"name":"SENSITIVE_TOOL","description":"SENSITIVE_DESCRIPTION"}}}}}`, true, false, 1, 0},
	} {
		got, err := projectAPIGatewayMCP(mcpRoot(t, tc.body))
		if err != nil || got["enabled"] != tc.enabled || got["global"] != tc.global || got["operation_opt_ins"] != tc.ins || got["operation_opt_outs"] != tc.outs {
			t.Fatal(tc, got, err)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "SENSITIVE") || strings.Contains(string(encoded), "secret") {
			t.Fatal(string(encoded))
		}
	}
}

func TestAPIGatewayMCPDiscoverySecurity(t *testing.T) {
	for _, tc := range []struct {
		scheme, security, rootSecurity string
		want                           string
		bad                            bool
	}{
		{`{"type":"apiKey","in":"header","name":"x-api-key"}`, `{"key":[]}`, ``, "api_key", false},
		{`{"type":"apiKey","in":"query","name":"key"}`, `{"key":[]}`, ``, "", true},
		{`{"type":"apiKey","in":"header","name":"x-api-key"}`, `{}`, ``, "", true},
		{`{"type":"apiKey","in":"header","name":"x-api-key"}`, `[{"key":[]}]`, ``, "", true},
		{`{"type":"apiKey","in":"header","name":"x-api-key"}`, `{"key":[],"other":[]}`, ``, "", true},
		{`{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"","scopes":{}}},"x-google-auth":{"issuer":"SENSITIVE_ISSUER"}}`, `{"key":[]}`, `,"security":[{"key":[]}]`, "jwt", false},
		{`{"type":"http","scheme":"bearer","x-google-auth":{"issuer":"SENSITIVE_ISSUER"}}`, `{"key":[]}`, ``, "", true},
		{`{"$ref":"https://evil.invalid"}`, `{"key":[]}`, ``, "", true},
	} {
		body := `{"openapi":"3.0.3","paths":{},"x-google-api-management":{"mcp":{"tools-list":{"security":` + tc.security + `}}},"components":{"securitySchemes":{"key":` + tc.scheme + `}}` + tc.rootSecurity + `}`
		got, err := projectAPIGatewayMCP(mcpRoot(t, body))
		if (err != nil) != tc.bad || (!tc.bad && got["tools_list_auth"] != tc.want) {
			t.Fatal(tc, got, err)
		}
		if tc.bad && got["complete"] != false {
			t.Fatal(got)
		}
	}
}

func TestAPIGatewayMCPMalformedIsUnknown(t *testing.T) {
	for _, extra := range []string{
		`"x-google-api-management":{"mcp":"true"},"paths":{}`,
		`"x-google-api-management":{"mcp":{"tools-list":null}},"paths":{}`,
		`"x-google-mcp-tool":true,"paths":{}`,
		`"paths":{"/x":{"x-google-mcp-tool":true}}`,
		`"paths":{"/x":{"get":{"x-google-mcp-tool":null}}}`,
		`"paths":{"/x":{"options":{"x-google-mcp-tool":true}}}`,
		`"paths":{"/x":{"post":{"x-google-mcp-tool":true,"x-google-model-router":"r"}}}`,
		`"paths":{"/x":{"get":{"x-google-mcp-tool":{"name":"bad name"}}}}`,
	} {
		got, err := projectAPIGatewayMCP(mcpRoot(t, `{"openapi":"3.0.3",`+extra+`}`))
		if err == nil || got["complete"] != false {
			t.Fatal(extra, got, err)
		}
	}
}

func TestAPIGatewayMCPDeclaredToolEligibility(t *testing.T) {
	for _, tc := range []struct {
		paths string
		count int
		bad   bool
	}{
		{`{}`, 0, false},
		{`{"/x":{"get":{"x-google-mcp-tool":false}}}`, 0, false},
		{`{"/x":{"options":{"operationId":"option","summary":"Options"}}}`, 0, false},
		{`{"/x":{"get":{"operationId":"tool","summary":"Tool"}}}`, 1, false},
		{`{"/x":{"get":{"summary":"Tool"}}}`, 0, true},
		{`{"/x":{"get":{"operationId":"tool"}}}`, 0, true},
		{`{"/x":{"get":{"operationId":"tool","summary":"Tool","x-google-backend":"missing"}}}`, 0, true},
		{`{"/x":{"get":{"operationId":"tool","summary":"Tool"}},"/y":{"post":{"operationId":"tool","summary":"Duplicate"}}}`, 0, true},
	} {
		root := mcpRoot(t, `{"openapi":"3.0.3","x-google-api-management":{"mcp":true,"backends":{"default":{"address":"https://example.invalid"}}},"x-google-backend":"default","paths":`+tc.paths+`}`)
		got, err := projectAPIGatewayMCP(root)
		if (err != nil) != tc.bad || (!tc.bad && got["eligible_declared_tools"] != tc.count) {
			t.Fatal(tc, got, err)
		}
	}
}

func TestAPIGatewayMCPYAMLBooleanSpellings(t *testing.T) {
	for _, value := range []string{"true", "True", "TRUE"} {
		for _, global := range []bool{true, false} {
			body := "openapi: 3.0.3\nx-google-api-management:\n  mcp: " + value + "\npaths: {}\n"
			if !global {
				body = "openapi: 3.0.3\nx-google-api-management:\n  backends:\n    default:\n      address: https://example.invalid\nx-google-backend: default\npaths:\n  /x:\n    get:\n      operationId: tool\n      summary: Tool\n      x-google-mcp-tool: " + value + "\n"
			}
			got, err := projectAPIGatewayMCP(mcpRoot(t, body))
			if err != nil || got["enabled"] != true || got["global"] != global {
				t.Fatal(value, global, got, err)
			}
		}
	}
}
