package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func viewerSQLGKEClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Synthetic capabilities isolate collector behavior, not role membership.
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.instances.list": true, "cloudsql.users.list": true, "cloudsql.databases.list": true, "cloudsql.backupRuns.list": true, "cloudsql.backupRuns.get": true, "container.clusters.list": true}
	return c
}

func TestViewerSQLGKERetainsPublicMetadataAfterInvalidRows(t *testing.T) {
	c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"items":[{"name":"foreign","project":"other"},{"name":"public-db","project":"demo","ipAddresses":[{"type":"PRIMARY","ipAddress":"8.8.8.8"}]}]}`), nil
	})
	s := Snapshot{}
	c.viewerSQL(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	s = Snapshot{}
	err := viewerGKEPage(&s, Object{"clusters": []any{Object{"name": "bad", "location": "us-central1", "selfLink": "https://container.googleapis.com/v1/projects/foreign/locations/us-central1/clusters/bad"}, Object{"name": "good", "location": "us-central1", "endpoint": "8.8.8.8"}}}, "demo", "projects/123")
	if err == nil || len(s.Assets) != 1 || Str(s.Assets[0].Resource.Data["endpoint"]) != "8.8.8.8" {
		t.Fatal(s, err)
	}
}

func TestViewerSQLGKEConfigAndPagination(t *testing.T) {
	sqlCalls := 0
	c := viewerSQLGKEClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		if r.URL.Host == "sqladmin.googleapis.com" {
			if strings.HasSuffix(r.URL.Path, "/users") || strings.HasSuffix(r.URL.Path, "/databases") || strings.HasSuffix(r.URL.Path, "/backupRuns") {
				return response(200, `{}`), nil
			}
			sqlCalls++
			if r.URL.Path != "/v1/projects/demo/instances" || r.URL.Query().Get("maxResults") != "1000" {
				t.Fatal(r.URL)
			}
			if sqlCalls == 1 {
				return response(200, `{"items":[{"name":"db-one","project":"demo","region":"us-central1","settings":{"ipConfiguration":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"items":[{"name":"db-two","project":"demo","selfLink":"https://sqladmin.googleapis.com/v1/projects/demo/instances/db-two"}]}`), nil
		}
		if r.URL.Host != "container.googleapis.com" || r.URL.Path != "/v1/projects/demo/locations/-/clusters" || len(r.URL.Query()) != 0 {
			t.Fatal(r.URL)
		}
		return response(200, `{"clusters":[{"name":"regional","location":"us-central1","legacyAbac":{"enabled":true},"nodePools":[{"name":"pool","config":{"workloadMetadataConfig":{"mode":"GCE_METADATA"}}}],"selfLink":"https://container.googleapis.com/v1/projects/demo/locations/us-central1/clusters/regional"},{"name":"zonal","zone":"us-east1-b","selfLink":"https://container.googleapis.com/v1/projects/123/zones/us-east1-b/clusters/zonal"}]}`), nil
	})
	var s Snapshot
	c.CollectViewerSQLGKE(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 4 || sqlCalls != 2 {
		t.Fatal(s, sqlCalls)
	}
	if s.Assets[0].Name != "//cloudsql.googleapis.com/projects/demo/instances/db-one" || Str(Get(s.Assets[0].Resource.Data, "settings", "ipConfiguration", "sslMode")) != "ALLOW_UNENCRYPTED_AND_ENCRYPTED" {
		t.Fatal(s.Assets[0])
	}
	if s.Assets[2].Name != "//container.googleapis.com/projects/demo/locations/us-central1/clusters/regional" || !Bool(Get(s.Assets[2].Resource.Data, "legacyAbac", "enabled")) || len(List(s.Assets[2].Resource.Data["nodePools"])) != 1 {
		t.Fatal(s.Assets[2])
	}
}

func TestViewerSQLWarningsKeepLaterPages(t *testing.T) {
	calls := 0
	c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"warnings":[{"code":"REGION_UNREACHABLE","message":"PRIVATE"}],"items":[{"name":"one","project":"demo"}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"items":[{"name":"two","project":"demo"}]}`), nil
	})
	var s Snapshot
	c.viewerSQL(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("warning contents leaked")
	}
}

func TestViewerSQLLatePermissionFailureRetainsRows(t *testing.T) {
	calls := 0
	c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"items":[{"name":"one","project":"demo"}],"nextPageToken":"next"}`), nil
		}
		return response(403, "PRIVATE upstream details"), nil
	})
	var s Snapshot
	c.viewerSQL(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("upstream error leaked")
	}
}

func TestViewerSQLMalformedAndCrossProject(t *testing.T) {
	for _, body := range []string{`{"items":{}}`, `{"items":[{"name":"db","project":"other"}]}`, `{"items":[{"name":"db","project":"demo","selfLink":"https://sqladmin.googleapis.com/v1/projects/other/instances/db"}]}`, `{"items":[null]}`, `{"warnings":{}}`, `{"nextPageToken":23}`} {
		c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerSQL(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerGKEPartialAndMalformed(t *testing.T) {
	for _, body := range []string{`{"clusters":[{"name":"good","location":"us-central1"}],"missingZones":["us-east1-b"]}`, `{"clusters":[{"name":"good","location":"us-central1"}],"unreachable":["us-east1"]}`, `{"clusters":[{"name":"good","location":"us-central1"}],"nextPageToken":"unexpected"}`} {
		c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerGKE(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
	for _, body := range []string{`null`, `{"clusters":{}}`, `{"clusters":[{"name":"bad","location":"../../escape"}]}`, `{"clusters":[{"name":"bad","location":"us-central1","selfLink":"https://container.googleapis.com/v1/projects/other/locations/us-central1/clusters/bad"}]}`, `{"missingZones":{}}`} {
		c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerGKE(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerSQLGKEIdentityAndMissingPermission(t *testing.T) {
	c := viewerSQLGKEClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })
	var s Snapshot
	c.CollectViewerSQLGKE(context.Background(), &s, "../bad", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerSQLGKE(context.Background(), &s, "demo", "projects/123")
	failed := 0
	for _, coverage := range s.Coverage {
		if coverage.Status == "failed" {
			failed++
		}
	}
	if failed != 2 || len(s.Assets) != 0 {
		t.Fatal(s)
	}
}
