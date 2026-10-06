package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerAppCheckResourcePoliciesScopedProjectionAndPagination(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "firebaseappcheck.googleapis.com" || r.Method != "GET" {
			t.Fatal(r.URL)
		}
		if r.URL.Path == "/v1/projects/123/services" {
			return response(200, `{"services":[{"name":"projects/123/services/oauth2.googleapis.com","enforcementMode":"ENFORCED"}]}`), nil
		}
		if r.URL.Path != "/v1/projects/123/services/oauth2.googleapis.com/resourcePolicies" || r.URL.Query().Get("fields") != viewerAppCheckResourcePolicyFields || r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		calls++
		if calls == 1 {
			return response(200, `{"resourcePolicies":[{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/foreign","targetResource":"//oauth2.googleapis.com/projects/999/oauthClients/client"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"resourcePolicies":[{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/123-client.apps.googleusercontent.com","enforcementMode":"OFF","etag":"SENTINEL","replayProtection":"SENTINEL"},{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/missing-mode","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/another"}]}`), nil
	})
	var out Snapshot
	c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 3 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[1].Type != FirebaseAppCheckResourcePolicyType || out.Assets[1].Resource.Data["enforcementMode"] != "OFF" || out.Assets[2].Resource.Data["enforcementMode"] != nil {
		t.Fatal(out.Assets)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal("unsafe field retained")
	}
}

func TestViewerAppCheckResourcePoliciesFixedParentAndPermissionOnly(t *testing.T) {
	for _, service := range []string{"firestore.googleapis.com", "oauth2.googleapis.com"} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path != "/v1/projects/123/services" {
				t.Fatal("unverified parent or baseline used", r.URL)
			}
			return response(200, `{"services":[{"name":"projects/123/services/`+service+`","enforcementMode":"OFF"}]}`), nil
		})
		delete(c.viewerPolicy.permissions, "firebaseappcheck.resourcePolicies.get")
		var out Snapshot
		c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
		if calls != 1 || len(out.Assets) != 1 {
			t.Fatal(out)
		}
		if !hasCoverage(out, "failed") {
			t.Fatal(out)
		}
	}
}

func TestViewerAppCheckResourcePolicyGuardAndLateFailure(t *testing.T) {
	endpoint := "https://firebaseappcheck.googleapis.com/v1/projects/123/services/oauth2.googleapis.com/resourcePolicies"
	q := url.Values{"fields": {viewerAppCheckResourcePolicyFields}, "pageSize": {"100"}}
	permissions, e := viewerRequestPermissions("GET", endpoint, q)
	if e != nil || len(permissions) != 1 || permissions[0] != "firebaseappcheck.resourcePolicies.get" {
		t.Fatal(permissions, e)
	}
	for _, tc := range []struct {
		method, path string
		q            url.Values
	}{{"POST", endpoint, q}, {"GET", strings.Replace(endpoint, "oauth2", "firestore", 1), q}, {"GET", endpoint + "/policy", q}, {"GET", endpoint, url.Values{"fields": {"*"}, "pageSize": {"100"}}}, {"GET", endpoint, url.Values{"fields": {viewerAppCheckResourcePolicyFields}, "pageSize": {"100"}, "filter": {"x"}}}} {
		if _, e := viewerRequestPermissions(tc.method, tc.path, tc.q); e == nil {
			t.Fatal(tc)
		}
	}
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"resourcePolicies":[{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/client","enforcementMode":"UNENFORCED"}],"nextPageToken":"next"}`), nil
		}
		return response(403, `DENIAL_SENTINEL`), nil
	})
	var out Snapshot
	c.viewerAppCheckResourcePolicies(context.Background(), &out, "projects/123")
	if calls != 2 || len(out.Assets) != 1 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}

func TestViewerAppCheckPoliciesIndependentOfServiceBaseline(t *testing.T) {
	for _, denied := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/v1/projects/123/services" {
				if denied {
					return response(403, `{}`), nil
				}
				return response(200, `{}`), nil
			}
			if r.URL.Path != "/v1/projects/123/services/oauth2.googleapis.com/resourcePolicies" {
				t.Fatal(r.URL)
			}
			calls++
			return response(200, `{"resourcePolicies":[{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/client","enforcementMode":"UNENFORCED"}]}`), nil
		})
		var out Snapshot
		c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
		if calls != 1 || len(out.Assets) != 1 || out.Assets[0].Type != FirebaseAppCheckResourcePolicyType || hasCoverage(out, "failed") != denied {
			t.Fatal(out)
		}
	}
}
