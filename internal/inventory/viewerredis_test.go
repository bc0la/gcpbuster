package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerRedisAggregatePaginationProjection(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		if r.Method != "GET" || r.URL.Host != "redis.googleapis.com" || r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/locations/-/instances":
			if r.URL.Query().Get("fields") != viewerRedisInstanceFields {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"instances":[{"name":"projects/123/locations/us-central1/instances/cache","state":"READY","authEnabled":false,"transitEncryptionMode":"DISABLED","authorizedNetwork":"projects/demo/global/networks/default","authString":"SOURCE_SENTINEL","redisConfigs":{"secret":"SOURCE_SENTINEL"}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"instances":[{"name":"projects/demo/locations/us-east1/instances/second","tier":"STANDARD_HA","persistenceConfig":{"persistenceMode":"RDB"}}]}`), nil
		case "/v1/projects/demo/locations/-/clusters":
			if r.URL.Query().Get("fields") != viewerRedisClusterFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"clusters":[{"name":"projects/demo/locations/us-central1/clusters/cluster","state":"ACTIVE","authorizationMode":"AUTH_MODE_DISABLED","transitEncryptionMode":"TRANSIT_ENCRYPTION_MODE_DISABLED","pscConfigs":[{"network":"projects/host/global/networks/net"}],"aclPolicy":"SOURCE_SENTINEL"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = map[string]bool{"redis.instances.list": true, "redis.clusters.list": true}
	var s Snapshot
	c.CollectViewerRedis(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("sensitive field leak")
	}
	if s.Assets[0].Name != "//redis.googleapis.com/projects/demo/locations/us-central1/instances/cache" {
		t.Fatal(s)
	}
}
func TestViewerRedisPartialUnknownAndScope(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "clusters") {
			return response(200, `{}`), nil
		}
		if r.URL.Query().Get("pageToken") == "next" {
			return response(200, `{"instances":[{"name":"projects/demo/locations/us-east1/instances/valid","authEnabled":true}],"unreachable":["SOURCE_SENTINEL"]}`), nil
		}
		return response(200, `{"instances":[{"name":"projects/other/locations/us-central1/instances/foreign"},{"name":"projects/demo/locations/us-central1/instances/partial","authEnabled":"false","state":"SOURCE_SENTINEL","transitEncryptionMode":"DISABLED"}],"nextPageToken":"next"}`), nil
	})
	var s Snapshot
	c.CollectViewerRedis(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if _, exists := s.Assets[0].Resource.Data["authEnabled"]; exists {
		t.Fatal("malformed bool retained")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("unknown enum/error leak")
	}
}
func TestViewerRedisDenialAndNoDefaultInference(t *testing.T) {
	clean, ok := viewerRedisProjection(Object{"name": "projects/demo/locations/us-central1/instances/cache"}, "demo", "projects/123", "instances")
	if !ok || len(clean) != 1 {
		t.Fatal(clean, ok)
	}
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) { calls++; return response(403, "SOURCE_SENTINEL"), nil })
	var s Snapshot
	c.CollectViewerRedis(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	before := calls
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerRedis(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
