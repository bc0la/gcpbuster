package inventory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}
func testClient(t *testing.T, fn roundTrip) *Client {
	t.Helper()
	t.Setenv("GCPBUSTER_TEST_TOKEN", "test-only-token")
	c := &Client{TokenEnv: "GCPBUSTER_TEST_TOKEN", HTTP: &http.Client{Transport: fn}}
	// Synthetic capabilities isolate historical collector behavior. These are
	// NOT the real Viewer permissions; viewerpolicy_test uses real-denial shapes.
	permissions := map[string]bool{}
	for _, entry := range viewerEndpoints {
		for _, p := range entry.permissions {
			permissions[p] = true
		}
	}
	for _, resource := range []string{"projects", "folders", "organizations"} {
		for _, action := range []string{"get", "list", "getIamPolicy"} {
			permissions["resourcemanager."+resource+"."+action] = true
		}
	}
	for _, resource := range []string{"projects", "folders", "organizations", "web", "webTypes", "webServices", "webServiceVersions", "tunnel", "tunnelZones", "tunnelInstances"} {
		for _, action := range []string{"getIamPolicy", "getSettings"} {
			permissions["iap."+resource+"."+action] = true
		}
	}
	for _, p := range []string{"cloudasset.assets.listResource", "cloudasset.assets.listIamPolicy", "cloudasset.assets.searchAllResources", "cloudasset.assets.searchAllIamPolicies", "storage.buckets.getIamPolicy"} {
		permissions[p] = true
	}
	c.viewerPolicy.permissions = permissions
	c.viewerPolicy.permissions["pubsub.schemas.list"] = true
	c.viewerPolicy.permissions["pubsub.schemas.listRevisions"] = true
	return c
}
func TestPaginationAndPartialFailure(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Fatal("unexpected request")
		}
		if calls == 1 {
			return response(200, `{"assets":[{"name":"first"}],"nextPageToken":"page2"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "page2" {
			t.Fatal("missing token")
		}
		return response(403, `sensitive upstream content`), nil
	})
	rows, err := c.list(context.Background(), "https://cloudresourcemanager.googleapis.com/v3/projects", nil, "assets")
	if len(rows) != 1 || err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("partial result/error: %+v %v", rows, err)
	}
}
func TestRepeatedPageToken(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"assets":[],"nextPageToken":"same"}`), nil
	})
	_, err := c.list(context.Background(), "https://cloudresourcemanager.googleapis.com/v3/projects", url.Values{}, "assets")
	if err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatal(err)
	}
}
func TestCloudCoverageAndReadTime(t *testing.T) {
	readTime := ""
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/projects/test/assets" {
			t.Fatal(r.URL)
		}
		q := r.URL.Query()
		if readTime == "" {
			readTime = q.Get("readTime")
		}
		if q.Get("readTime") != readTime || readTime == "" {
			t.Fatal("read time drift")
		}
		if q.Get("contentType") == "RESOURCE" {
			if len(q["assetTypes"]) == 0 {
				t.Fatal("missing resource filter")
			}
			return response(200, `{"assets":[]}`), nil
		}
		return response(403, `{}`), nil
	})
	s := c.Cloud(context.Background(), "projects/test")
	if calls != 2 || len(s.Coverage) != 2 || s.Coverage[0].Status != "completed" || s.Coverage[1].Status != "failed" {
		t.Fatalf("wrong coverage %+v", s)
	}
}
func TestWorkspaceCollectionBlockedByViewerBoundary(t *testing.T) {
	for _, tokens := range []bool{false, true} {
		t.Run(fmt.Sprint(tokens), func(t *testing.T) {
			tokenCalls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				t.Fatal("viewer-scoped client must not contact Workspace", r.URL)
				if r.Method != "GET" {
					t.Fatal("write request")
				}
				if strings.HasSuffix(r.URL.Path, "/users") {
					if r.URL.Query().Get("projection") != "full" {
						t.Fatal("incomplete projection")
					}
					return response(200, `{"users":[{"id":"user1","isEnrolledIn2Sv":false}]}`), nil
				}
				if strings.HasSuffix(r.URL.Path, "/tokens") {
					tokenCalls++
					return response(200, `{"items":[{"clientId":"app1","scopes":["openid"]}]}`), nil
				}
				return response(200, `{}`), nil
			})
			s := c.Workspace(context.Background(), "my_customer", tokens)
			if len(s.Assets) != 0 || tokenCalls != 0 || !hasCoverage(s, "failed") {
				t.Fatalf("unexpected collection %+v", s)
			}
		})
	}
}
