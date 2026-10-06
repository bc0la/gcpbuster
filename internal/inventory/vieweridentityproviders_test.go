package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerIdentityProvidersScopesPaginationAndRedaction(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "foreign") {
			t.Fatal(r.URL)
		}
		if strings.HasSuffix(r.URL.Path, "inboundSamlConfigs") {
			return response(200, `{}`), nil
		}
		calls++
		if strings.Contains(r.URL.Path, "/tenants/") {
			return response(200, `{"oauthIdpConfigs":[{"name":"projects/123/tenants/one/oauthIdpConfigs/oidc.test","enabled":true,"responseType":{"idToken":true,"code":true}}]}`), nil
		}
		if r.URL.Query().Get("pageToken") == "next" {
			return response(200, `{"oauthIdpConfigs":[{"name":"projects/123/oauthIdpConfigs/oidc.second","enabled":true,"responseType":{"idToken":true}}]}`), nil
		}
		return response(200, `{"oauthIdpConfigs":[{"name":"projects/foreign/oauthIdpConfigs/oidc.bad"},{"name":"projects/demo/oauthIdpConfigs/oidc.test","enabled":true,"responseType":{"code":true},"clientSecret":"SECRET_SENTINEL","issuer":"SECRET_SENTINEL"}],"nextPageToken":"next"}`), nil
	})
	out := Snapshot{Assets: []Asset{NewAsset("//identitytoolkit.googleapis.com/projects/123/tenants/one", "identitytoolkit.googleapis.com/Tenant", Object{}), NewAsset("//identitytoolkit.googleapis.com/projects/foreign/tenants/bad", "identitytoolkit.googleapis.com/Tenant", Object{})}}
	c.CollectViewerIdentityProviders(context.Background(), &out, "demo", "projects/123")
	if calls != 3 || len(out.Assets) != 5 || !hasCoverage(out, "failed") {
		t.Fatal(calls, out)
	}
	if out.Assets[4].Resource.Data["projection_complete"] != false || out.Assets[4].Resource.Data["responseType"] != nil {
		t.Fatal(out.Assets[4])
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("source retained")
	}
}
func TestViewerIdentityProvidersGuardAndPermission(t *testing.T) {
	ep := "https://identitytoolkit.googleapis.com/v2/projects/123/oauthIdpConfigs"
	q := url.Values{"fields": {viewerOIDCFields}, "pageSize": {"100"}}
	p, e := viewerRequestPermissions("GET", ep, q)
	if e != nil || len(p) != 1 || p[0] != "firebaseauth.configs.get" {
		t.Fatal(p, e)
	}
	for _, bad := range []url.Values{{"fields": {"*"}, "pageSize": {"100"}}, {"fields": {viewerOIDCFields}, "pageSize": {"100"}, "clientSecret": {"true"}}} {
		if _, e := viewerRequestPermissions("GET", ep, bad); e == nil {
			t.Fatal(bad)
		}
	}
	for _, path := range []string{ep + "/oidc.id", strings.Replace(ep, "123", "demo", 1), ep + ":create"} {
		if _, e := viewerRequestPermissions("GET", path, q); e == nil {
			t.Fatal(path)
		}
	}
	if _, e := viewerRequestPermissions("POST", ep, q); e == nil {
		t.Fatal("write allowed")
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network"); return nil, nil })
	delete(c.viewerPolicy.permissions, "firebaseauth.configs.get")
	var out Snapshot
	c.CollectViewerIdentityProviders(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
func TestViewerIdentityProvidersLateFailureRetainsMetadata(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "inboundSamlConfigs") {
			return response(200, `{}`), nil
		}
		if r.URL.Query().Get("pageToken") != "" {
			return response(403, `SENSITIVE_DENIAL`), nil
		}
		return response(200, `{"oauthIdpConfigs":[{"name":"projects/123/oauthIdpConfigs/oidc.one"}],"nextPageToken":"next"}`), nil
	})
	var out Snapshot
	c.CollectViewerIdentityProviders(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 1 || !hasCoverage(out, "failed") || out.Assets[0].Resource.Data["enabled"] != nil {
		t.Fatal(out)
	}
}

func TestViewerIdentityProvidersSAMLAndMalformedFlags(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/inboundSamlConfigs") {
			return response(200, `{"inboundSamlConfigs":[{"name":"projects/demo/inboundSamlConfigs/saml.one","enabled":false,"idpConfig":{"issuer":"SECRET_SENTINEL","idpCertificates":[{"x509Certificate":"SECRET_SENTINEL"}]}}]}`), nil
		}
		return response(200, `{"oauthIdpConfigs":[{"name":"projects/123/oauthIdpConfigs/oidc.one","enabled":true,"responseType":{"idToken":true,"code":"false"}},{"name":"projects/123/oauthIdpConfigs/oidc.two","enabled":true,"responseType":{"idToken":true,"token":true}},{"name":"projects/123/oauthIdpConfigs/oidc.three","enabled":null}]}`), nil
	})
	var out Snapshot
	c.CollectViewerIdentityProviders(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 4 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	for _, a := range out.Assets[:3] {
		if a.Resource.Data["projection_complete"] != false || a.Resource.Data["responseType"] != nil {
			t.Fatal(a)
		}
	}
	a := out.Assets[3]
	if a.Type != IdentityPlatformSAMLProviderType || a.Resource.Data["enabled"] != false || a.Resource.Data["name"] != "projects/123/inboundSamlConfigs/saml.one" {
		t.Fatal(a)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("SAML source retained")
	}
}
