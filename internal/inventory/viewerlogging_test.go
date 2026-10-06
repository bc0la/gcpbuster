package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func viewerLoggingClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"logging.buckets.list": true, "resourcemanager.projects.get": true}
	return c
}

func TestViewerLogBucketsPaginationProjectionAndAliases(t *testing.T) {
	calls := 0
	c := viewerLoggingClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "logging.googleapis.com" || r.URL.Path != "/v2/projects/123/locations/-/buckets" || r.URL.Query().Get("fields") != viewerLogBucketFields {
			t.Fatal(r.URL)
		}
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"buckets":[{"name":"projects/demo/locations/global/buckets/_Default","retentionDays":30,"locked":false,"restrictedFields":["jsonPayload.password"],"cmekSettings":{"kmsKeyName":"projects/demo/locations/us-central1/keyRings/r/cryptoKeys/k","payload":"PRIVATE"},"entries":["PRIVATE"]}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"buckets":[{"name":"projects/123/locations/eu/buckets/archive","retentionDays":365,"locked":true,"lifecycleState":"ACTIVE","analyticsEnabled":true}]}`), nil
	})
	s := Snapshot{Assets: []Asset{NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", Object{"name": "projects/123", "projectId": "demo"})}}
	c.CollectViewerLogBuckets(context.Background(), &s, []string{"projects/demo", "projects/123"})
	if calls != 2 || len(s.Assets) != 3 || hasCoverage(s, "failed") || s.Assets[1].Name != "//logging.googleapis.com/projects/123/locations/global/buckets/_Default" {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("non-metadata retained")
	}
}

func TestViewerLogBucketsResolveScopeAndContinueDeniedParent(t *testing.T) {
	c := viewerLoggingClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "cloudresourcemanager.googleapis.com" {
			if r.URL.Path != "/v3/projects/demo" {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"projects/123","projectId":"demo"}`), nil
		}
		if strings.Contains(r.URL.Path, "organizations/1/") {
			return response(403, "PRIVATE"), nil
		}
		if strings.Contains(r.URL.Path, "projects/123/") {
			return response(200, `{}`), nil
		}
		if r.URL.Path != "/v2/folders/2/locations/-/buckets" {
			t.Fatal(r.URL)
		}
		return response(200, `{"buckets":[{"name":"folders/2/locations/us-central1/buckets/archive"}]}`), nil
	})
	var s Snapshot
	c.CollectViewerLogBuckets(context.Background(), &s, []string{"organizations/1", "projects/demo", "folders/2"})
	if !hasCoverage(s, "failed") || len(s.Assets) != 1 || s.Assets[0].Name != "//logging.googleapis.com/folders/2/locations/us-central1/buckets/archive" {
		t.Fatal(s)
	}
}

func TestViewerLogBucketsMalformedAndForeignRowsRetainSafe(t *testing.T) {
	for _, bad := range []string{`null`, `{"name":"projects/other/locations/global/buckets/x"}`, `{"name":"projects/123/locations/-/buckets/x"}`, `{"name":"projects/123/locations/global/buckets/x","locked":"false"}`, `{"name":"projects/123/locations/global/buckets/x","retentionDays":-1}`, `{"name":"projects/123/locations/global/buckets/x","retentionDays":1.2}`, `{"name":"projects/123/locations/global/buckets/x","cmekSettings":[]}`} {
		c := viewerLoggingClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"buckets":[{"name":"projects/123/locations/global/buckets/_Required"},`+bad+`]}`), nil
		})
		var s Snapshot
		c.CollectViewerLogBuckets(context.Background(), &s, []string{"projects/123"})
		if !hasCoverage(s, "failed") || len(s.Assets) != 1 {
			t.Fatal(bad, s)
		}
	}
}

func TestViewerLogBucketsPartialAndPermissions(t *testing.T) {
	for _, permission := range []bool{true, false} {
		c := viewerLoggingClient(t, func(r *http.Request) (*http.Response, error) {
			if !permission {
				t.Fatal("guard allowed request")
			}
			if r.URL.Query().Get("pageToken") != "" {
				return response(403, "PRIVATE"), nil
			}
			return response(200, `{"buckets":[{"name":"projects/123/locations/global/buckets/_Default"}],"nextPageToken":"next"}`), nil
		})
		if !permission {
			c.viewerPolicy.permissions = map[string]bool{}
		}
		var s Snapshot
		c.CollectViewerLogBuckets(context.Background(), &s, []string{"projects/123"})
		if !hasCoverage(s, "failed") || (permission && len(s.Assets) != 1) {
			t.Fatal(s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal("upstream error retained")
		}
	}
}

func TestViewerLoggingConfigWhitelistsAndValidatesBooleans(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "logging.googleapis.com" || r.URL.Query().Get("fields") == "" {
			t.Fatal(r.URL)
		}
		if strings.HasSuffix(r.URL.Path, "/exclusions") {
			return response(200, `{"exclusions":[{"name":"metadata","filter":"severity=DEBUG","disabled":false,"entries":"PRIVATE"}]}`), nil
		}
		return response(200, `{"sinks":[{"name":"good","destination":"logging.googleapis.com/projects/demo/locations/global/buckets/_Default","disabled":false,"bigqueryOptions":{"usePartitionedTables":true,"entries":"PRIVATE"},"exclusions":[{"name":"nested","filter":"severity=DEBUG","disabled":true,"entries":"PRIVATE"}],"entries":"PRIVATE"},{"name":"bad","disabled":"false"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"logging.sinks.list": true, "logging.exclusions.list": true}
	var s Snapshot
	c.CollectLoggingConfig(context.Background(), &s, []string{"projects/demo"})
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("non-configuration data retained")
	}
	for _, d := range []Object{{"name": "x", "interceptChildren": 42}, {"name": "x", "includeChildren": "true"}, {"name": "x", "exclusions": []any{Object{"name": "e", "disabled": 42}}}, {"name": "x", "bigqueryOptions": Object{"usePartitionedTables": "true"}}} {
		if _, err := viewerLoggingConfigProjection(d, true); err == nil {
			t.Fatal("malformed config accepted", d)
		}
	}
}
