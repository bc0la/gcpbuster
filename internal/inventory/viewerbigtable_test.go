package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerBigtableMetadataAndVersionedIAM(t *testing.T) {
	lists := 0
	iam := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			iam++
			b, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(b) != `{"options":{"requestedPolicyVersion":3}}` || r.URL.RawQuery != "" {
				t.Fatal(r.Method, string(b), r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/bigtable.reader","members":["user:a@example.test"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`), nil
		}
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		switch r.URL.Path {
		case "/v2/projects/demo/instances":
			if len(r.URL.Query()) != 1 {
				t.Fatal(r.URL)
			}
			return response(200, `{"instances":[{"name":"projects/123/instances/db","state":"READY","displayName":"SECRET_SENTINEL"}]}`), nil
		case "/v2/projects/demo/instances/db/tables":
			lists++
			if r.URL.Query().Get("view") != "NAME_ONLY" {
				t.Fatal(r.URL)
			}
			if lists == 1 {
				return response(200, `{"tables":[{"name":"projects/123/instances/db/tables/t1"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"tables":[{"name":"projects/demo/instances/db/tables/t2"}]}`), nil
		case "/v2/projects/demo/instances/db/tables/t1", "/v2/projects/demo/instances/db/tables/t2":
			if r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != viewerBigtableTableFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"`+strings.TrimPrefix(r.URL.Path, "/v2/")+`","deletionProtection":false,"columnFamilies":{"SECRET_SENTINEL":{}},"rowKeySchema":{"secret":"SECRET_SENTINEL"},"changeStreamConfig":{"retentionPeriod":"86400s"},"automatedBackupPolicy":{"retentionPeriod":"604800s","frequency":"86400s"}}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"bigtable.instances.list": true, "bigtable.tables.list": true, "bigtable.tables.get": true, "bigtable.instances.getIamPolicy": true, "bigtable.tables.getIamPolicy": true}
	s := Snapshot{}
	c.CollectViewerBigtable(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || lists != 2 || iam != 3 || hasCoverage(s, "failed") || hasCoverage(s, "partial") {
		t.Fatal(s, lists, iam)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal(string(b))
	}
	if len(List(s.Assets[1].IAM["bindings"])) != 1 {
		t.Fatal(s)
	}
}

func TestViewerBigtableScopeUnknownAndPartial(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/v2/projects/demo/instances":
			return response(200, `{"failedLocations":["unknown"],"instances":[{"name":"projects/foreign/instances/db"},{"name":"projects/demo/instances/db"}]}`), nil
		case "/v2/projects/demo/instances/db/tables":
			if r.URL.Query().Get("pageToken") == "next" {
				return response(403, `{}`), nil
			}
			return response(200, `{"tables":[{"name":"projects/demo/instances/other/tables/foreign"},{"name":"projects/demo/instances/db/tables/valid"}],"nextPageToken":"next"}`), nil
		case "/v2/projects/demo/instances/db/tables/valid":
			return response(200, `{"name":"projects/demo/instances/db/tables/other","deletionProtection":false}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"bigtable.instances.list": true, "bigtable.tables.list": true, "bigtable.tables.get": true}
	s := Snapshot{}
	c.CollectViewerBigtable(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || calls != 4 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	if _, ok := s.Assets[1].Resource.Data["deletionProtection"]; ok {
		t.Fatal("foreign metadata retained")
	}
	name := "projects/demo/instances/db/tables/t"
	d, ok := projectViewerBigtableTable(Object{"name": name, "deletionProtection": "false", "changeStreamConfig": Object{"retentionPeriod": "SECRET"}, "automatedBackupPolicy": nil}, name, "demo", "projects/123")
	if ok || len(d) != 1 {
		t.Fatal(d, ok)
	}
}

func TestViewerBigtableStrictGuard(t *testing.T) {
	base := "https://bigtableadmin.googleapis.com/v2/projects/demo/instances"
	for _, tc := range []struct {
		path       string
		q          url.Values
		permission string
	}{{"", url.Values{"fields": {viewerBigtableInstanceFields}}, "bigtable.instances.list"}, {"/db/tables", url.Values{"fields": {viewerBigtableTableListFields}, "view": {"NAME_ONLY"}, "pageSize": {"100"}}, "bigtable.tables.list"}, {"/db/tables/t", url.Values{"fields": {viewerBigtableTableFields}, "view": {"FULL"}}, "bigtable.tables.get"}} {
		p, e := viewerRequestPermissions("GET", base+tc.path, tc.q)
		if e != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, e)
		}
		for _, key := range []string{"filter", "alt", "unexpected"} {
			q := url.Values{}
			for k, v := range tc.q {
				q[k] = v
			}
			q.Set(key, "x")
			if _, e := viewerRequestPermissions("GET", base+tc.path, q); e == nil {
				t.Fatal(q)
			}
		}
	}
	for _, bad := range []url.Values{{"fields": {viewerBigtableTableListFields}, "view": {"FULL"}, "pageSize": {"100"}}, {"fields": {"*"}, "view": {"NAME_ONLY"}, "pageSize": {"100"}}} {
		if _, e := viewerRequestPermissions("GET", base+"/db/tables", bad); e == nil {
			t.Fatal(bad)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("blocked reached transport"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{"bigtable.tables.readRows": true, "bigtable.tables.sampleRowKeys": true, "bigtable.tables.mutateRows": true, "bigtable.instances.executeQuery": true, "bigtable.tables.getIamPolicy": true}
	for _, path := range []string{"/db/tables/t:readRows", "/db/tables/t:sampleRowKeys", "/db/tables/t:dropRowRange", "/db:executeQuery", "/db/tables/t:setIamPolicy"} {
		if _, e := c.readIAMPolicy(context.Background(), base+path); e == nil {
			t.Fatal(path)
		}
	}
	s := Snapshot{}
	c.CollectViewerBigtable(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if _, e := viewerRequestPermissions("POST", base+"/db/tables/t:getIamPolicy", url.Values{"options.requestedPolicyVersion": {"1"}}); e == nil {
		t.Fatal("IAM query accepted")
	}
}
