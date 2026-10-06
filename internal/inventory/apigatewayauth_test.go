package inventory

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func authDocument(source string) Object {
	return Object{"openapiDocuments": []any{Object{"document": Object{"contents": base64.StdEncoding.EncodeToString([]byte(source)), "path": "SOURCE_SENTINEL"}}}}
}

func TestAPIGatewayAuthInheritanceAndOverrides(t *testing.T) {
	source := `swagger: "2.0"
securityDefinitions:
  key: {type: apiKey, in: query, name: key}
  jwt: {type: oauth2, flow: implicit, x-google-issuer: https://SOURCE_SENTINEL}
security: [{key: []}]
paths:
  /SOURCE_SENTINEL:
    get: {}
    post: {security: []}
    put: {security: [{jwt: []}]}
    patch: {security: [{jwt: [], key: []}]}
    delete: {security: [{key: []}, {}]}
`
	got, err := projectAPIGatewayAuth(authDocument(source))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"GET": "api_key", "POST": "none", "PUT": "jwt", "PATCH": "mixed", "DELETE": "optional"}
	for _, raw := range got["routes"].([]any) {
		r := Obj(raw)
		if want[Str(r["method"])] != r["auth"] {
			t.Fatal(r)
		}
		delete(want, Str(r["method"]))
		if len(Str(r["route_digest"])) != 64 {
			t.Fatal(r)
		}
	}
	if len(want) != 0 || got["complete"] != true {
		t.Fatal(got)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SOURCE_SENTINEL") || strings.Contains(string(encoded), "https:") {
		t.Fatal("source leaked")
	}
	for _, security := range []string{"", "security: []\n"} {
		got, err = projectAPIGatewayAuth(authDocument("swagger: '2.0'\n" + security + "paths: {'/': {get: {}}}\n"))
		if err != nil || Obj(got["routes"].([]any)[0])["auth"] != "none" {
			t.Fatal(got, err)
		}
	}
}

func TestAPIGatewayAuthPartialUnsupportedInheritance(t *testing.T) {
	source := `swagger: "2.0"
security: [{unknown: []}]
paths:
  /safe: {get: {security: []}, post: {}}
  /ref: {$ref: 'https://SOURCE_SENTINEL'}
  /invalid: {security: [], get: {}}
`
	got, err := projectAPIGatewayAuth(authDocument(source))
	if err == nil || got["complete"] != false || len(got["routes"].([]any)) != 1 || Obj(got["routes"].([]any)[0])["method"] != "GET" {
		t.Fatal(got, err)
	}
	if strings.Contains(err.Error(), "SOURCE_SENTINEL") {
		t.Fatal("error leaked")
	}
}

func TestAPIGatewayAuthRejectsAmbiguity(t *testing.T) {
	for _, source := range []string{
		"swagger: '2.0'\npaths: {}\n---\npaths: {}", "swagger: '2.0'\npaths: {}\npaths: {}", "swagger: '2.0'\npaths: &a {}\nx: *a", "openapi: '3.2.0'\npaths: {}", "swagger: '2.0'\nx-google-management: {}\npaths: {}", "SOURCE_SENTINEL: [",
	} {
		if got, err := projectAPIGatewayAuth(authDocument(source)); err == nil || got != nil || strings.Contains(err.Error(), "SOURCE_SENTINEL") {
			t.Fatal("expected sanitized rejection", got, err)
		}
	}
	valid := authDocument("swagger: '2.0'\npaths: {}")
	for _, field := range []string{"grpcServices", "managedServiceConfigs"} {
		raw := authDocument("swagger: '2.0'\npaths: {}")
		raw[field] = []any{Object{}}
		if _, err := projectAPIGatewayAuth(raw); err == nil {
			t.Fatal(field)
		}
	}
	valid["openapiDocuments"] = append(valid["openapiDocuments"].([]any), Object{})
	if _, err := projectAPIGatewayAuth(valid); err == nil {
		t.Fatal("multiple documents accepted")
	}
	for _, contents := range []string{"%%%SOURCE_SENTINEL", strings.Repeat("A", base64.StdEncoding.EncodedLen(apiGatewayAuthMaxBytes)+1)} {
		raw := Object{"openapiDocuments": []any{Object{"document": Object{"contents": contents}}}}
		if _, err := projectAPIGatewayAuth(raw); err == nil {
			t.Fatal("bad encoding accepted")
		}
	}
}

func TestAPIGatewayAuthUnsupportedRequirementsNotAnonymous(t *testing.T) {
	prefix := "swagger: '2.0'\nsecurityDefinitions:\n  key: {type: apiKey, in: query, name: key}\n  jwt: {type: oauth2, flow: implicit, x-google-issuer: issuer}\n  jwt2: {type: oauth2, flow: implicit, x-google-issuer: issuer2}\npaths:\n  /:\n    get:\n      security: "
	for _, security := range []string{"null", "{}", "[{missing: []}]", "[{key: []}, {jwt: []}]", "[{jwt: []}, {}]", "[{jwt: [], jwt2: []}]", "[{key: [scope]}]", "[{jwt: null}]"} {
		got, err := projectAPIGatewayAuth(authDocument(prefix + security + "\n"))
		if err == nil || len(got["routes"].([]any)) != 0 {
			t.Fatal(security, got, err)
		}
	}
}

func TestAPIGatewayAuthOpenAPI3Inheritance(t *testing.T) {
	for _, version := range []string{"3.0.0", "3.0.3", "3.1.0", "3.1.1"} {
		source := `openapi: VERSION
components:
  securitySchemes:
    key: {type: apiKey, in: header, name: x-api-key}
    jwt:
      type: oauth2
      flows: {implicit: {authorizationUrl: "", scopes: {}}}
      x-google-auth: {issuer: SOURCE_SENTINEL, jwksUri: 'https://SOURCE_SENTINEL'}
security: [{jwt: []}]
paths:
  /SOURCE_SENTINEL:
    summary: SOURCE_SENTINEL
    servers: [{url: 'https://SOURCE_SENTINEL'}]
    get: {}
    post: {security: []}
    trace: {security: [{key: []}, {}]}
    patch: {security: [{key: [], jwt: []}]}
`
		got, err := projectAPIGatewayAuth(authDocument(strings.ReplaceAll(source, "VERSION", version)))
		if err != nil {
			t.Fatal(err)
		}
		if got["version"] != version || got["complete"] != true {
			t.Fatal(got)
		}
		want := map[string]string{"GET": "jwt", "POST": "none", "TRACE": "optional", "PATCH": "mixed"}
		for _, raw := range got["routes"].([]any) {
			r := Obj(raw)
			if want[Str(r["method"])] != r["auth"] {
				t.Fatal(r)
			}
			delete(want, Str(r["method"]))
		}
		if len(want) != 0 {
			t.Fatal(want)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SOURCE_SENTINEL") {
			t.Fatal("source leak")
		}
	}
}

func TestAPIGatewayAuthOpenAPI3UnsupportedIsPartial(t *testing.T) {
	for _, scheme := range []string{`{type: http, scheme: bearer}`, `{type: openIdConnect, openIdConnectUrl: 'https://SOURCE_SENTINEL'}`, `{$ref: '#/components/securitySchemes/another'}`, `{type: oauth2, flows: {}, x-google-auth: {issuer: issuer}}`} {
		source := "openapi: 3.0.3\ncomponents:\n  securitySchemes:\n    unsupported: " + scheme + "\nsecurity: [{unsupported: []}]\npaths:\n  /:\n    get: {}\n    post: {security: []}\n"
		got, err := projectAPIGatewayAuth(authDocument(source))
		if err == nil || got["complete"] != false || len(got["routes"].([]any)) != 1 {
			t.Fatal(got, err)
		}
	}
	for _, source := range []string{"openapi: 3.0.3\nswagger: '2.0'\npaths: {}", "openapi: 3.0.3\nsecurityDefinitions: {}\npaths: {}", "openapi: 3.0.3\ncomponents: null\npaths: {}"} {
		if _, err := projectAPIGatewayAuth(authDocument(source)); err == nil {
			t.Fatal("ambiguous format accepted")
		}
	}
}

func TestAPIGatewayAuthMCPFailureRetainsRoutes(t *testing.T) {
	source := "openapi: 3.0.3\nx-google-api-management:\n  mcp: SOURCE_SENTINEL\npaths:\n  /:\n    get: {security: []}\n"
	got, err := projectAPIGatewayAuth(authDocument(source))
	if err == nil || got["complete"] != false || len(got["routes"].([]any)) != 1 || Obj(got["mcp"])["complete"] != false {
		t.Fatal(got, err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SOURCE_SENTINEL") || strings.Contains(err.Error(), "SOURCE_SENTINEL") {
		t.Fatal("source leak")
	}
}
