package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerMemcacheAggregateProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "memcache.googleapis.com" || r.URL.Path != "/v1/projects/demo/locations/-/instances" || r.URL.Query().Get("fields") != viewerMemcacheFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"instances":[{"name":"projects/123/locations/us-central1/instances/cache","state":"READY","nodeCount":2,"memcacheVersion":"MEMCACHE_1_5","zones":["us-central1-a"],"authorizedNetwork":"projects/demo/global/networks/default","parameters":{"secret":"PRIVATE_SENTINEL"},"discoveryEndpoint":"PRIVATE_SENTINEL"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"memcache.instances.list": true}
	out := Snapshot{}
	c.CollectViewerMemcache(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 1 || hasCoverage(out, "failed") {
		t.Fatal(out, calls)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE_SENTINEL") {
		t.Fatal(string(b))
	}
}

func TestViewerMemcachePartialAndRoleGate(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return response(200, `{"instances":[{"name":"projects/foreign/locations/us-central1/instances/cache"},{"name":"projects/demo/locations/us-central1/instances/cache","nodeCount":"2","state":"PRIVATE_SENTINEL"},{"name":"projects/demo/locations/us-east1/instances/valid","state":"READY"}],"unreachable":["us-west1"]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"memcache.instances.list": true}
	out := Snapshot{}
	c.CollectViewerMemcache(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 2 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE_SENTINEL") {
		t.Fatal(string(b))
	}
	c.viewerPolicy.permissions = map[string]bool{}
	c.CollectViewerMemcache(context.Background(), &out, "demo", "projects/123")
	c.CollectViewerMemcache(context.Background(), &out, "../invalid", "projects/123")
	if calls != 1 {
		t.Fatal(calls)
	}
}
