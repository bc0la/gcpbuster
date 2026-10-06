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

func TestViewerSpannerScopedPaginationAndIAM(t *testing.T) {
	pages := map[string]int{}
	iam := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			iam++
			b, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(b) != `{"options":{"requestedPolicyVersion":3}}` {
				t.Fatal(r.Method, string(b))
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/spanner.databaseReader","members":["user:a@example.test"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`), nil
		}
		if r.Method != "GET" || r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		pages[r.URL.Path]++
		page := pages[r.URL.Path]
		if page == 2 {
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{}`), nil
		}
		switch r.URL.Path {
		case "/v1/projects/demo/instances":
			return response(200, `{"instances":[{"name":"projects/123/instances/inst","state":"READY","displayName":"SECRET_SENTINEL","labels":{"secret":"SECRET_SENTINEL"}}],"nextPageToken":"next"}`), nil
		case "/v1/projects/demo/instances/inst/databases":
			return response(200, `{"databases":[{"name":"projects/123/instances/inst/databases/db","enableDropProtection":false,"databaseDialect":"GOOGLE_STANDARD_SQL","versionRetentionPeriod":"1h","schema":"SECRET_SENTINEL"}],"nextPageToken":"next"}`), nil
		case "/v1/projects/demo/instances/inst/backups":
			return response(200, `{"backups":[{"name":"projects/123/instances/inst/backups/bk","database":"projects/demo/instances/inst/databases/db","expireTime":"2030-01-01T00:00:00Z","state":"READY","contents":"SECRET_SENTINEL"}],"nextPageToken":"next"}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"spanner.instances.list": true, "spanner.databases.list": true, "spanner.backups.list": true, "spanner.instances.getIamPolicy": true, "spanner.databases.getIamPolicy": true, "spanner.backups.getIamPolicy": true}
	s := Snapshot{}
	c.CollectViewerSpanner(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || iam != 3 || hasCoverage(s, "failed") {
		t.Fatal(s, iam)
	}
	for path, count := range pages {
		if count != 2 {
			t.Fatal(path, count)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal(string(b))
	}
	if len(List(s.Assets[1].IAM["bindings"])) != 1 {
		t.Fatal(s)
	}
}

func TestViewerSpannerForeignMalformedAndLateDenial(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/v1/projects/demo/instances":
			return response(200, `{"instances":[{"name":"projects/foreign/instances/inst"},{"name":"projects/demo/instances/inst"}],"unreachable":["inst2"]}`), nil
		case "/v1/projects/demo/instances/inst/databases":
			if r.URL.Query().Get("pageToken") != "" {
				return response(403, `{}`), nil
			}
			return response(200, `{"databases":[{"name":"projects/demo/instances/other/databases/db"},{"name":"projects/demo/instances/inst/databases/db","enableDropProtection":"false","databaseDialect":"GOOGLE_STANDARD_SQL|POSTGRESQL","versionRetentionPeriod":"SECRET"}],"nextPageToken":"next"}`), nil
		case "/v1/projects/demo/instances/inst/backups":
			return response(200, `{}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"spanner.instances.list": true, "spanner.databases.list": true, "spanner.backups.list": true}
	s := Snapshot{}
	c.CollectViewerSpanner(context.Background(), &s, "demo", "projects/123")
	if calls != 4 || len(s.Assets) != 2 || !hasCoverage(s, "failed") || len(s.Assets[1].Resource.Data) != 1 {
		t.Fatal(s, calls)
	}
}

func TestViewerSpannerStrictReadGuard(t *testing.T) {
	base := "https://spanner.googleapis.com/v1/projects/demo/instances"
	for _, tc := range []struct{ path, fields, permission string }{{"", viewerSpannerInstanceFields, "spanner.instances.list"}, {"/inst/databases", viewerSpannerDatabaseFields, "spanner.databases.list"}, {"/inst/backups", viewerSpannerBackupFields, "spanner.backups.list"}} {
		q := url.Values{"fields": {tc.fields}, "pageSize": {"100"}}
		p, e := viewerRequestPermissions("GET", base+tc.path, q)
		if e != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, e)
		}
		q.Set("filter", "x")
		if _, e := viewerRequestPermissions("GET", base+tc.path, q); e == nil {
			t.Fatal(q)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe request reached network")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"spanner.sessions.create": true, "spanner.databases.select": true, "spanner.databases.read": true, "spanner.backups.copy": true, "spanner.backups.restoreDatabase": true, "spanner.databases.updateDdl": true}
	for _, path := range []string{"/inst/databases/db/sessions", "/inst/databases/db/sessions/s:executeSql", "/inst/databases/db/sessions/s:read", "/inst/databases/db/sessions/s:commit", "/inst/backups/bk:copy", "/inst/databases:restore", "/inst/databases/db/ddl", "/inst/databases/db:setIamPolicy"} {
		if _, e := c.readIAMPolicy(context.Background(), base+path); e == nil {
			t.Fatal(path)
		}
	}
	s := Snapshot{}
	c.CollectViewerSpanner(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	for _, name := range []string{"instances", "databases", "backups", "ddl"} {
		if _, e := viewerRequestPermissions("GET", base+"/inst/databases/"+name+"/ddl", url.Values{"fields": {"statements"}}); e != nil {
			t.Fatal(e)
		}
		if _, e := viewerRequestPermissions("GET", base+"/inst/databases/"+name+"/ddl", url.Values{"fields": {"statements,protoDescriptors"}}); e == nil {
			t.Fatal("extra DDL fields")
		}
	}
}

func TestViewerSpannerCrossProjectLineageProjection(t *testing.T) {
	name := "projects/demo/instances/inst/databases/db"
	d, ok := projectViewerSpanner(Object{"restoreInfo": Object{"sourceType": "BACKUP", "backupInfo": Object{"backup": "projects/foreign/instances/source/backups/bk", "sourceDatabase": "projects/456/instances/source/databases/db", "createTime": "2026-01-01T00:00:00Z", "versionTime": "2026-01-01T00:00:00Z", "secret": "DO_NOT_RETAIN"}}}, name, "Database", "demo", "projects/123")
	if !ok || Str(Obj(Obj(d["restoreInfo"])["backupInfo"])["sourceDatabase"]) != "projects/456/instances/source/databases/db" {
		t.Fatal(d, ok)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "DO_NOT_RETAIN") {
		t.Fatal(string(b))
	}
	d, ok = projectViewerSpanner(Object{"database": "projects/foreign/instances/source/databases/db"}, "projects/demo/instances/inst/backups/bk", "Backup", "demo", "projects/123")
	if !ok || Str(d["database"]) == "" {
		t.Fatal(d, ok)
	}
	for _, bad := range []string{"https://other.invalid/x", "projects/foreign/instances/source/databases/../db", "projects/foreign/instances/source/databases/x?secret=y"} {
		if viewerSpannerReference(bad, "demo", "projects/123", "Database") != "" {
			t.Fatal(bad)
		}
	}
}
