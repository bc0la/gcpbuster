package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerAlloyDBAggregatePaginationProjection(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		if r.Method != "GET" || r.URL.Host != "alloydb.googleapis.com" || r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/locations/-/clusters":
			if r.URL.Query().Get("fields") != viewerAlloyDBClusterFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"clusters":[{"name":"projects/123/locations/us-central1/clusters/cluster","state":"READY","initialUser":{"password":"SOURCE_SENTINEL"}}]}`), nil
		case "/v1/projects/demo/locations/-/clusters/-/instances":
			if r.URL.Query().Get("fields") != viewerAlloyDBInstanceFields {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"instances":[{"name":"projects/demo/locations/us-central1/clusters/cluster/instances/main","state":"READY","instanceType":"PRIMARY","networkConfig":{"enablePublicIp":true,"authorizedExternalNetworks":[{"cidrRange":"0.0.0.0/0"}]},"clientConnectionConfig":{"requireConnectors":false,"sslConfig":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}},"dataApiAccess":"ENABLED","databaseFlags":{"secret":"SOURCE_SENTINEL"}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"instances":[{"name":"projects/demo/locations/us-east1/clusters/second/instances/read","instanceType":"READ_POOL"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = map[string]bool{"alloydb.clusters.list": true, "alloydb.instances.list": true}
	var s Snapshot
	c.CollectViewerAlloyDB(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("sensitive metadata leaked")
	}
}
func TestViewerAlloyDBProjectionUnknownAndScope(t *testing.T) {
	name := "projects/demo/locations/us-central1/clusters/cluster/instances/main"
	raw := Object{"name": name, "state": "READY|STOPPED", "dataApiAccess": "SOURCE_SENTINEL", "networkConfig": Object{"enablePublicIp": "true", "authorizedExternalNetworks": []any{Object{"cidrRange": "bad"}, Object{"cidrRange": "192.0.2.3/24"}}}, "clientConnectionConfig": Object{"sslConfig": Object{"sslMode": "SOURCE_SENTINEL"}}}
	clean, ok := viewerAlloyDBProjection(raw, "demo", "projects/123", "Instance")
	if ok || clean == nil || len(List(Get(clean, "networkConfig", "authorizedExternalNetworks"))) != 1 {
		t.Fatal(clean, ok)
	}
	b, _ := json.Marshal(clean)
	if strings.Contains(string(b), "SOURCE_SENTINEL") || strings.Contains(string(b), "READY|") {
		t.Fatal("unknown enum leaked")
	}
	for _, bad := range []string{"projects/other/locations/us-central1/clusters/cluster/instances/main", "projects/demo/locations/-/clusters/cluster/instances/main", name + "/extra"} {
		if clean, _ := viewerAlloyDBProjection(Object{"name": bad}, "demo", "projects/123", "Instance"); clean != nil {
			t.Fatal(clean)
		}
	}
}
func TestViewerAlloyDBPartialAndRoleGate(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/instances") {
			return response(403, "SOURCE_SENTINEL"), nil
		}
		return response(200, `{"clusters":[{"name":"projects/other/locations/us-central1/clusters/bad"},{"name":"projects/demo/locations/us-central1/clusters/good"}],"unreachable":["SOURCE_SENTINEL"]}`), nil
	})
	var s Snapshot
	c.CollectViewerAlloyDB(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	before := calls
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerAlloyDB(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
