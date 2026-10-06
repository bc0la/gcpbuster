package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerServiceUsagePaginationProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "serviceusage.googleapis.com" || r.URL.Path != "/v1/projects/123/services" || r.URL.Query().Get("filter") != "state:ENABLED" || r.URL.Query().Get("fields") != viewerServiceUsageFields || r.URL.Query().Get("pageSize") != "200" {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"services":[{"name":"projects/123/services/compute.googleapis.com","parent":"projects/123","state":"ENABLED","config":{"name":"compute.googleapis.com","documentation":{"secret":"SOURCE_SENTINEL"},"title":"SOURCE_SENTINEL"}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"services":[{"name":"projects/123/services/compute.googleapis.com","state":"ENABLED"},{"name":"projects/123/services/run.googleapis.com","state":"ENABLED"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"serviceusage.services.list": true}
	var s Snapshot
	c.CollectViewerServiceUsage(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("source leak")
	}
}
func TestViewerServiceUsageScopeAndMalformed(t *testing.T) {
	for _, body := range []string{`{"services":false}`, `{"services":[null]}`, `{"services":[{"name":"projects/999/services/run.googleapis.com","state":"ENABLED"}]}`, `{"services":[{"name":"projects/123/services/run.googleapis.com","state":"DISABLED"}]}`, `{"services":[{"name":"projects/123/services/run.googleapis.com","state":"ENABLED","parent":"projects/demo"}]}`, `{"services":[{"name":"projects/123/services/run.googleapis.com","state":"ENABLED","config":{"name":"other.googleapis.com"}}]}`, `{"services":[{"name":"projects/123/services/https://secret","state":"ENABLED"}]}`, `{"nextPageToken":5}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		c.viewerPolicy.permissions = map[string]bool{"serviceusage.services.list": true}
		var s Snapshot
		c.CollectViewerServiceUsage(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}
func TestViewerServiceUsagePartialAndRoleGate(t *testing.T) {
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"services":[{"name":"projects/123/services/run.googleapis.com","state":"ENABLED"}],"nextPageToken":"denied"}`), nil
		}
		return response(403, "SOURCE_SENTINEL"), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"serviceusage.services.list": true}
	var s Snapshot
	c.CollectViewerServiceUsage(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("error body leaked")
	}
	c.viewerPolicy.permissions = map[string]bool{}
	before := calls
	s = Snapshot{}
	c.CollectViewerServiceUsage(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
}

func TestViewerServiceUsageRetainsValidAfterInvalid(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"services":[{"name":"projects/999/services/bad.googleapis.com","state":"ENABLED"},{"name":"projects/123/services/run.googleapis.com","state":"ENABLED"},{"name":"projects/123/services/bad.googleapis.com","state":"ENABLED","config":null},{"name":"projects/123/services/storage.googleapis.com","state":"ENABLED"}],"nextPageToken":"more"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "more" {
			t.Fatal(r.URL)
		}
		return response(200, `{"services":[{"name":"projects/123/services/compute.googleapis.com","state":"ENABLED"}]}`), nil
	})
	var s Snapshot
	c.CollectViewerServiceUsage(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 3 || !hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
}
