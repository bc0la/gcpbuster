package inventory

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerServerlessDirectIAMScopedVersionThree(t *testing.T) {
	for _, tc := range []struct{ host, version, collection, kind, permission string }{{"run.googleapis.com", "v2", "services", "Service", "run.services.getIamPolicy"}, {"cloudfunctions.googleapis.com", "v1", "functions", "CloudFunction", "cloudfunctions.functions.getIamPolicy"}, {"cloudfunctions.googleapis.com", "v2", "functions", "Function", "cloudfunctions.functions.getIamPolicy"}} {
		t.Run(tc.host+tc.version, func(t *testing.T) {
			region := "us-central1"
			if tc.collection == "functions" {
				region = "-"
			}
			calls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
					if r.Method != "GET" || r.URL.Query().Get("options.requestedPolicyVersion") != "3" || r.URL.Query().Get("fields") != "version,bindings,etag" || !strings.Contains(r.URL.Path, "/projects/demo/locations/us-central1/"+tc.collection+"/good:") {
						t.Fatal(r.URL)
					}
					return response(200, `{"version":3,"bindings":[{"role":"roles/run.invoker","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`), nil
				}
				return response(200, `{"`+tc.collection+`":[{"name":"projects/foreign/locations/us-central1/`+tc.collection+`/bad"},{"name":"projects/123/locations/us-central1/`+tc.collection+`/good"}]}`), nil
			})
			s := Snapshot{}
			c.viewerServerlessList(context.Background(), &s, "demo", "projects/123", tc.host, tc.version, region, tc.collection, tc.kind)
			if calls != 2 || len(s.Assets) != 1 || len(List(s.Assets[0].IAM["bindings"])) != 1 || !hasCoverage(s, "failed") {
				t.Fatal(s, calls)
			}
			delete(c.viewerPolicy.permissions, tc.permission)
			calls = 0
			s = Snapshot{}
			c.viewerServerlessList(context.Background(), &s, "demo", "projects/123", tc.host, tc.version, region, tc.collection, tc.kind)
			if calls != 1 || len(s.Assets) != 1 || s.Assets[0].IAM != nil || !hasCoverage(s, "failed") {
				t.Fatal(s, calls)
			}
		})
	}
}

func TestViewerGen2FunctionExplicitRunPolicyFallback(t *testing.T) {
	function := func(ref string) Asset {
		a := NewAsset("//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/fn", "cloudfunctions.googleapis.com/Function", Object{"name": "projects/123/locations/us-central1/functions/fn", "serviceConfig": Object{"service": ref}})
		a.Ancestors = []string{"projects/123"}
		return a
	}
	ref := "projects/123/locations/us-central1/services/backing"
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v2/projects/demo/locations/us-central1/services/backing:getIamPolicy" {
			t.Fatal(r.URL)
		}
		return response(200, `{"bindings":[{"role":"roles/run.invoker","members":["allUsers"]}]}`), nil
	})
	s := Snapshot{Assets: []Asset{function(ref)}}
	c.viewerFunctionRunPolicies(context.Background(), &s, "demo", "projects/123")
	if calls != 1 || len(s.Assets) != 2 || len(List(s.Assets[1].IAM["bindings"])) != 1 {
		t.Fatal(s, calls)
	}
	c.viewerFunctionRunPolicies(context.Background(), &s, "demo", "projects/123")
	if calls != 1 {
		t.Fatal("duplicate service policy read")
	}
	for _, bad := range []string{"projects/foreign/locations/us-central1/services/backing", "projects/demo/locations/us-east1/services/backing", "https://evil.invalid/path"} {
		calls = 0
		s = Snapshot{Assets: []Asset{function(bad)}}
		c.viewerFunctionRunPolicies(context.Background(), &s, "demo", "projects/123")
		if calls != 0 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
			t.Fatal(s, calls)
		}
	}
	calls = 0
	s = Snapshot{Assets: []Asset{function(ref), function("projects/demo/locations/us-central1/services/other")}}
	c.viewerFunctionRunPolicies(context.Background(), &s, "demo", "projects/123")
	if calls != 0 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
}

func TestViewerServerlessIAMGuard(t *testing.T) {
	for _, base := range []string{"https://run.googleapis.com/v2/projects/demo/locations/us-central1/services/web", "https://cloudfunctions.googleapis.com/v1/projects/demo/locations/us-central1/functions/web", "https://cloudfunctions.googleapis.com/v2/projects/demo/locations/us-central1/functions/web"} {
		q := url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}}
		if _, e := viewerRequestPermissions("GET", base+":getIamPolicy", q); e != nil {
			t.Fatal(e)
		}
		for _, action := range []string{":setIamPolicy", ":call", ":run", ":generateDownloadUrl"} {
			if _, e := viewerRequestPermissions("GET", base+action, q); e == nil {
				t.Fatal(action)
			}
		}
		for _, bad := range []url.Values{{"options.requestedPolicyVersion": {"1"}, "fields": {"version,bindings,etag"}}, {"options.requestedPolicyVersion": {"3"}, "fields": {"*"}}, {"options.requestedPolicyVersion": {"3", "3"}, "fields": {"version,bindings,etag"}}} {
			if _, e := viewerRequestPermissions("GET", base+":getIamPolicy", bad); e == nil {
				t.Fatal(bad)
			}
		}
		if _, e := viewerRequestPermissions("POST", base+":getIamPolicy", q); e == nil {
			t.Fatal("wrong method")
		}
	}
}
