package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func compiledAuthFixture() Object {
	return Object{"apis": []any{Object{"name": "example.SOURCE_SENTINEL", "methods": []any{Object{"name": "Read"}, Object{"name": "Write"}}}}, "authentication": Object{"rules": []any{Object{"selector": "*"}}}, "usage": Object{"rules": []any{Object{"selector": "*", "allowUnregisteredCalls": true}}}}
}
func TestServiceManagementAuthLastMatchAndProjection(t *testing.T) {
	raw := compiledAuthFixture()
	raw["authentication"] = Object{"providers": []any{Object{"id": "jwt", "issuer": "SOURCE_SENTINEL"}}, "rules": []any{Object{"selector": "example.SOURCE_SENTINEL.Read", "requirements": []any{Object{"providerId": "jwt"}}}, Object{"selector": "example.*"}}}
	got, err := projectServiceManagementAuth(raw)
	if err != nil || got["complete"] != true {
		t.Fatal(got, err)
	}
	for _, m := range got["methods"].([]any) {
		if Obj(m)["authentication"] != "none" || Obj(m)["consumer_identity"] != "not_required" {
			t.Fatal(m)
		}
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SOURCE_SENTINEL") || strings.Contains(string(encoded), "Read") {
		t.Fatal("source leaked")
	}
	raw["usage"] = Object{"rules": []any{Object{"selector": "*", "allowUnregisteredCalls": true}, Object{"selector": "example.SOURCE_SENTINEL.Read, example.SOURCE_SENTINEL.Write", "allowUnregisteredCalls": false}}}
	got, err = projectServiceManagementAuth(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range got["methods"].([]any) {
		if Obj(m)["consumer_identity"] != "required" {
			t.Fatal(m)
		}
	}
}
func TestServiceManagementAuthCredentialCombinations(t *testing.T) {
	for _, tc := range []struct {
		rule Object
		mode string
	}{{Object{"selector": "*"}, "none"}, {Object{"selector": "*", "allowWithoutCredential": true}, "api_key_alternative"}, {Object{"selector": "*", "requirements": []any{Object{"providerId": "jwt"}}}, "jwt"}, {Object{"selector": "*", "requirements": []any{Object{"providerId": "jwt"}}, "allowWithoutCredential": true}, "api_key_alternative"}, {Object{"selector": "*", "oauth": Object{"canonicalScopes": "scope"}}, "oauth"}} {
		raw := compiledAuthFixture()
		raw["authentication"] = Object{"providers": []any{Object{"id": "jwt", "issuer": "issuer"}}, "rules": []any{tc.rule}}
		got, err := projectServiceManagementAuth(raw)
		if err != nil || Obj(got["methods"].([]any)[0])["authentication"] != tc.mode {
			t.Fatal(got, err)
		}
	}
}
func TestServiceManagementAuthUnknownIsNotAnonymous(t *testing.T) {
	for _, change := range []func(Object){func(o Object) {
		o["usage"] = Object{"rules": []any{Object{"selector": "*", "allowUnregisteredCalls": true, "skipServiceControl": true}}}
	}, func(o Object) {
		o["authentication"] = Object{"rules": []any{Object{"selector": "*", "requirements": []any{Object{"providerId": "missing"}}}}}
	}, func(o Object) {
		o["authentication"] = Object{"rules": []any{Object{"selector": "*", "allowWithoutCredential": "false"}}}
	}, func(o Object) {
		o["authentication"] = Object{"rules": []any{Object{"selector": "*", "oauth": Object{}}}}
	}} {
		raw := compiledAuthFixture()
		change(raw)
		got, err := projectServiceManagementAuth(raw)
		if err == nil || got["complete"] != false {
			t.Fatal(got, err)
		}
		for _, r := range got["methods"].([]any) {
			m := Obj(r)
			if m["authentication"] == "none" && m["consumer_identity"] == "not_required" {
				t.Fatal("false anonymous")
			}
		}
	}
}
func TestServiceManagementAuthRejectsMalformedSelectors(t *testing.T) {
	for _, selector := range []string{"", "example*", "example.*.Read", "example.Read,", "https://SOURCE_SENTINEL"} {
		raw := compiledAuthFixture()
		raw["usage"] = Object{"rules": []any{Object{"selector": selector, "allowUnregisteredCalls": true}}}
		if got, err := projectServiceManagementAuth(raw); err == nil || got != nil || strings.Contains(err.Error(), "SOURCE_SENTINEL") {
			t.Fatal(got, err)
		}
	}
	for _, selector := range []string{"exampleOther.*", "example"} {
		raw := compiledAuthFixture()
		raw["usage"] = Object{"rules": []any{Object{"selector": selector, "allowUnregisteredCalls": true}}}
		got, err := projectServiceManagementAuth(raw)
		if err != nil || Obj(got["methods"].([]any)[0])["consumer_identity"] != "required" {
			t.Fatal("prefix overmatch")
		}
	}
}

func TestServiceManagementAuthCompiledDefaults(t *testing.T) {
	for _, field := range []string{"authentication", "usage"} {
		raw := compiledAuthFixture()
		delete(raw, field)
		got, err := projectServiceManagementAuth(raw)
		if err != nil {
			t.Fatal(err)
		}
		m := Obj(got["methods"].([]any)[0])
		if field == "authentication" {
			if m["authentication"] != "none" || m["authentication_source"] != "default" || m["consumer_identity"] != "not_required" {
				t.Fatal(m)
			}
		} else if m["consumer_identity"] != "required" || m["usage_source"] != "default" {
			t.Fatal(m)
		}
	}
	for _, field := range []string{"authentication", "usage"} {
		for _, value := range []any{nil, false, "SOURCE_SENTINEL", Object{"rules": nil}} {
			raw := compiledAuthFixture()
			raw[field] = value
			if got, err := projectServiceManagementAuth(raw); err == nil || got != nil {
				t.Fatal(got, err)
			}
		}
	}
}

func TestServiceManagementAuthEmptyCompiledMethods(t *testing.T) {
	for _, raw := range []Object{{}, {"apis": []any{}}, {"apis": []any{Object{"name": "example.Api"}}}} {
		got, err := projectServiceManagementAuth(raw)
		if err != nil || got["complete"] != true || len(got["methods"].([]any)) != 0 {
			t.Fatal(got, err)
		}
	}
	for _, raw := range []Object{{"apis": nil}, {"apis": false}, {"apis": []any{Object{"name": "example.Api", "methods": nil}}}, {"apis": []any{Object{"name": "example.Api", "methods": false}}}} {
		if got, err := projectServiceManagementAuth(raw); err == nil || got != nil {
			t.Fatal(got, err)
		}
	}
}
