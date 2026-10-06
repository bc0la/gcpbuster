package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func federationClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Exact API-reference spellings only, not assumed permission aliases.
	c.viewerPolicy.permissions = map[string]bool{"iam.workloadIdentityPools.list": true, "iam.workloadIdentityPoolProviders.list": true}
	return c
}

func TestViewerFederationMetadataPaginationAndProjection(t *testing.T) {
	pages := 0
	c := federationClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "iam.googleapis.com" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/123/locations/global/workloadIdentityPools":
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"nextPageToken":"next"}`), nil
			}
			return response(200, `{"workloadIdentityPools":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool","state":"ACTIVE"}]}`), nil
		case "/v1/projects/123/locations/global/workloadIdentityPools/pool/providers":
			pages++
			if strings.Contains(r.URL.Query().Get("fields"), "jwks") {
				t.Fatal("key data requested")
			}
			if pages == 1 {
				return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/123/locations/global/workloadIdentityPools/pool/providers/one","state":"ACTIVE","attributeCondition":"assertion.sub == 'a'","attributeMapping":{"google.subject":"assertion.sub"},"oidc":{"issuerUri":"https://never-follow.invalid","jwksJson":"FORBIDDEN_KEY"},"keys":"FORBIDDEN_KEYS"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool/providers/two","state":"ACTIVE","disabled":true,"aws":{"accountId":"123456789012"}}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerFederation(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || len(s.Assets) != 3 || pages != 2 {
		t.Fatal(s)
	}
	for _, a := range s.Assets {
		if !strings.Contains(a.Name, "/projects/demo/") || a.Resource.Location != "global" {
			t.Fatal(a)
		}
	}
	if Str(s.Assets[1].Resource.Data["attributeCondition"]) == "" || Str(Get(s.Assets[1].Resource.Data, "attributeMapping", "google.subject")) != "assertion.sub" {
		t.Fatal("trust config lost")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "FORBIDDEN") {
		t.Fatal(string(b))
	}
}

func TestViewerFederationInactiveOrUnknownParentsDoNotAssessProviders(t *testing.T) {
	for _, fields := range []string{`"state":"DELETED"`, `"state":"ACTIVE","disabled":true`, `"state":"ACTIVE","mode":"TRUST_DOMAIN"`, `"state":"STATE_UNSPECIFIED"`, `"disabled":"false"`, `"state":"ACTIVE","mode":42`} {
		t.Run(fields, func(t *testing.T) {
			calls := 0
			c := federationClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return response(200, `{"workloadIdentityPools":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool",`+fields+`}]}`), nil
			})
			s := Snapshot{}
			c.CollectViewerFederation(context.Background(), &s, "demo", "projects/123")
			if calls != 1 || len(s.Assets) != 1 {
				t.Fatal(s, calls)
			}
		})
	}
}

func TestViewerFederationMalformedProviderRetainsLaterPage(t *testing.T) {
	c := federationClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool/providers/unknown"}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool/providers/valid","state":"ACTIVE","oidc":{"issuerUri":"https://never-follow.invalid","allowedAudiences":["audience"]}}]}`), nil
	})
	s := Snapshot{}
	c.viewerFederationProviders(context.Background(), &s, "demo", "projects/123", "pool")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerFederationMalformedAndUnsupportedProviderUnion(t *testing.T) {
	for _, fields := range []string{
		``, `,"aws":{}`, `,"aws":null`, `,"aws":{"accountId":123}`, `,"aws":{"accountId":" "}`,
		`,"oidc":{}`, `,"oidc":{"issuerUri":false}`, `,"oidc":{"issuerUri":"https://issuer.invalid","allowedAudiences":"aud"}`,
		`,"oidc":{"issuerUri":"https://issuer.invalid","allowedAudiences":[3]}`,
		`,"oidc":{"issuerUri":"https://issuer.invalid","allowedAudiences":[""]}`,
		`,"aws":{"accountId":"123"},"oidc":{"issuerUri":"https://issuer.invalid"}`,
		`,"oidc":{"issuerUri":"https://issuer.invalid"},"saml":{}`,
		`,"saml":{"idpMetadataXml":"FORBIDDEN_CERT"}`, `,"x509":{}`,
	} {
		t.Run(fields, func(t *testing.T) {
			c := federationClient(t, func(r *http.Request) (*http.Response, error) {
				return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/demo/locations/global/workloadIdentityPools/pool/providers/invalid","state":"ACTIVE"`+fields+`}]}`), nil
			})
			s := Snapshot{}
			c.viewerFederationProviders(context.Background(), &s, "demo", "projects/123", "pool")
			if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerFederationRejectsForeignProviderAndQualifiedOnlyPermissions(t *testing.T) {
	c := federationClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"workloadIdentityPoolProviders":[{"name":"projects/elsewhere/locations/global/workloadIdentityPools/pool/providers/valid","state":"ACTIVE"}]}`), nil
	})
	s := Snapshot{}
	c.viewerFederationProviders(context.Background(), &s, "demo", "projects/123", "pool")
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c = federationClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("qualified permission implicitly aliased", r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"iam.googleapis.com/workloadIdentityPools.list": true, "iam.googleapis.com/workloadIdentityPoolProviders.list": true}
	s = Snapshot{}
	c.CollectViewerFederation(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
