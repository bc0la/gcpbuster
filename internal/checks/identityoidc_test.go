package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIdentityOIDCExplicitResponseAndGates(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"enabled":true,"responseType":{"idToken":true,"code":false}}`, 1},
		{`{"enabled":true,"responseType":{"idToken":true}}`, 1},
		{`{"enabled":false,"responseType":{"idToken":true}}`, 0},
		{`{"responseType":{"idToken":true}}`, 0},
		{`{"enabled":"true","responseType":{"idToken":true}}`, 0},
		{`{"enabled":true,"responseType":{"idToken":true,"code":true}}`, 0},
		{`{"enabled":true,"responseType":{"idToken":true,"code":"false"}}`, 0},
		{`{"enabled":true,"responseType":{"idToken":true,"token":true}}`, 0},
		{`{"enabled":true,"responseType":{"idToken":false,"code":true}}`, 0},
		{`{"enabled":true,"projection_complete":false,"responseType":{"idToken":true}}`, 0},
	} {
		a := asset("gcpbuster.googleapis.com/IdentityPlatformOIDCProvider", tc.body)
		a.Name = "//identitytoolkit.googleapis.com/projects/123/oauthIdpConfigs/oidc.example"
		a.Resource.Data["name"] = "projects/123/oauthIdpConfigs/oidc.example"
		got := identityOIDCResponseType(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestIdentityOIDCTenantScopeAndRedactedEvidence(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/IdentityPlatformOIDCProvider", `{"name":"projects/123/tenants/t/oauthIdpConfigs/oidc.example","enabled":true,"responseType":{"idToken":true,"code":false},"clientSecret":"SENTINEL","issuer":"https://SENTINEL","clientId":"SENTINEL"}`)
	a.Name = "//identitytoolkit.googleapis.com/projects/123/tenants/t/oauthIdpConfigs/oidc.example"
	got := identityOIDCResponseType(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	a.Resource.Data["name"] = "projects/999/tenants/t/oauthIdpConfigs/oidc.example"
	if len(identityOIDCResponseType(a, time.Now())) != 0 {
		t.Fatal("mismatched identity")
	}
	a.Type = "identitytoolkit.googleapis.com/Config"
	if len(identityOIDCResponseType(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}
