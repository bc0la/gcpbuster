package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func viewerDataClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/oauthIdpConfigs") || strings.HasSuffix(r.URL.Path, "/inboundSamlConfigs") {
			return response(200, `{}`), nil
		}
		if r.URL.Host == "firebaseappcheck.googleapis.com" {
			return response(200, `{}`), nil
		}
		return fn(r)
	})
	// Synthetic capabilities test dispatch, not the real predefined roles.
	c.viewerPolicy.permissions = map[string]bool{"firebaseappcheck.resourcePolicies.get": true, "firebaseappcheck.services.get": true, "bigquery.datasets.get": true, "bigquery.datasets.getIamPolicy": true, "firebaseauth.configs.get": true, "identitytoolkit.tenants.list": true, "identitytoolkit.tenants.get": true}
	return c
}

func TestViewerDataConfigDetailsAndSafeFields(t *testing.T) {
	listCalls := 0
	c := viewerDataClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		switch r.URL.Host + r.URL.Path {
		case "bigquery.googleapis.com/bigquery/v2/projects/demo/datasets":
			listCalls++
			if r.URL.Query().Get("all") != "true" {
				t.Fatal("hidden datasets excluded")
			}
			if listCalls == 1 {
				return response(200, `{"datasets":[],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"datasets":[{"datasetReference":{"projectId":"demo","datasetId":"_hidden"}}]}`), nil
		case "bigquery.googleapis.com/bigquery/v2/projects/demo/datasets/_hidden":
			if r.URL.Query().Get("datasetView") != "FULL" || r.URL.Query().Get("accessPolicyVersion") != "3" {
				t.Fatal("ACL/version missing", r.URL)
			}
			return response(200, `{"datasetReference":{"projectId":"demo","datasetId":"_hidden"},"location":"US","access":[{"iamMember":"allUsers","role":"READER","condition":{"expression":"true"}}]}`), nil
		case "identitytoolkit.googleapis.com/admin/v2/projects/123/config":
			if r.URL.Query().Get("fields") != viewerIdentityConfigFields {
				t.Fatal("unbounded config read", r.URL)
			}
			return response(200, `{"name":"projects/demo/config","signIn":{"anonymous":{"enabled":true},"hashConfig":{"signerKey":"PRIVATE"}},"mfa":{"state":"DISABLED"},"notification":{"sendEmail":{"smtp":{"password":"PRIVATE"}}}}`), nil
		case "identitytoolkit.googleapis.com/v2/projects/123/tenants":
			if r.URL.Query().Get("fields") != "tenants("+viewerIdentityTenantFields+"),nextPageToken" {
				t.Fatal("unbounded tenant list", r.URL)
			}
			return response(200, `{"tenants":[{"name":"projects/demo/tenants/tenant-one"}]}`), nil
		case "identitytoolkit.googleapis.com/v2/projects/123/tenants/tenant-one":
			if r.URL.Query().Get("fields") != viewerIdentityTenantFields {
				t.Fatal("unbounded tenant detail", r.URL)
			}
			return response(200, `{"name":"projects/123/tenants/tenant-one","enableAnonymousUser":true,"mfaConfig":{"state":"DISABLED"},"hashConfig":{"signerKey":"PRIVATE"},"testPhoneNumbers":{"111":"PRIVATE"}}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	var s Snapshot
	c.CollectViewerDataConfig(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") || listCalls != 2 {
		t.Fatal(s)
	}
	if s.Assets[0].Name != "//bigquery.googleapis.com/projects/demo/datasets/_hidden" || Str(Get(Obj(List(s.Assets[0].Resource.Data["access"])[0]), "condition", "expression")) != "true" {
		t.Fatal(s.Assets[0])
	}
	if s.Assets[1].Name != "//identitytoolkit.googleapis.com/projects/123/config" || !Bool(Get(s.Assets[1].Resource.Data, "signIn", "anonymous", "enabled")) || !Bool(s.Assets[2].Resource.Data["enableAnonymousUser"]) {
		t.Fatal(s.Assets)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("sensitive config retained")
	}
}

func TestViewerDatasetsPartialDetailAndMissingACL(t *testing.T) {
	c := viewerDataClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/datasets") {
			return response(200, `{"datasets":[{"datasetReference":{"projectId":"demo","datasetId":"denied"}},{"datasetReference":{"projectId":"demo","datasetId":"missing"}}]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/denied") {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{"datasetReference":{"projectId":"demo","datasetId":"missing"}}`), nil
	})
	var s Snapshot
	c.viewerDatasets(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("error leaked")
	}
}

func TestViewerDataIdentityRejectsForeignMalformed(t *testing.T) {
	for _, body := range []string{`{"datasets":{}}`, `{"datasets":[{"datasetReference":{"projectId":"other","datasetId":"bad"}}]}`, `{"datasets":[{"datasetReference":{"projectId":"demo","datasetId":"../bad"}}]}`, `{"nextPageToken":true}`} {
		c := viewerDataClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerDatasets(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(s)
		}
	}
	for _, name := range []string{"projects/999/config", "projects/demo/tenants/a/extra", "projects/demo/tenants/../bad"} {
		if _, err := viewerIdentityName(name, "demo", "projects/123", "Tenant"); err == nil {
			t.Fatal(name)
		}
	}
}

func TestViewerIdentityLateTenantFailureKeepsPosture(t *testing.T) {
	c := viewerDataClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			return response(404, "PRIVATE"), nil
		}
		if strings.HasSuffix(r.URL.Path, "/tenants/one") {
			return response(403, "PRIVATE"), nil
		}
		if r.URL.Query().Get("pageToken") == "next" {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{"tenants":[{"name":"projects/123/tenants/one","enableAnonymousUser":true}],"nextPageToken":"next"}`), nil
	})
	var s Snapshot
	c.viewerIdentityConfig(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !Bool(s.Assets[0].Resource.Data["enableAnonymousUser"]) || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("error leaked")
	}
}

func TestViewerDataConfigMissingPermissionsFailClosed(t *testing.T) {
	c := viewerDataClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network requested"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	var s Snapshot
	c.CollectViewerDataConfig(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerDatasetMalformedConditionsPreserveValidatedACL(t *testing.T) {
	for _, condition := range []string{`{}`, `"invalid"`, `[]`, `{"expression":""}`, `{"expression":"   "}`, `{"expression":true}`} {
		t.Run(condition, func(t *testing.T) {
			c := viewerDataClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/datasets") {
					return response(200, `{"datasets":[{"datasetReference":{"projectId":"demo","datasetId":"data"}}]}`), nil
				}
				return response(200, `{"datasetReference":{"projectId":"demo","datasetId":"data"},"access":[{"iamMember":"allUsers","role":"READER","condition":{"expression":"true"}},{"iamMember":"allAuthenticatedUsers","role":"READER","condition":`+condition+`}]}`), nil
			})
			var s Snapshot
			c.viewerDatasets(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
			access := List(s.Assets[0].Resource.Data["access"])
			if len(access) != 1 || Str(Get(Obj(access[0]), "condition", "expression")) != "true" {
				t.Fatal("valid ACL lost or malformed condition accepted", access)
			}
		})
	}
}
