package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerSQLDatabasesProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "sqladmin.googleapis.com" || r.URL.Path != "/v1/projects/demo/instances/db/databases" || r.URL.Query().Get("fields") != viewerSQLDatabaseFields || len(r.URL.Query()) != 1 {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":[{"name":"app db","project":"demo","instance":"db","charset":"utf8mb4","collation":"utf8mb4_bin","selfLink":"https://sqladmin.googleapis.com/sql/v1/projects/demo/instances/db/databases/app%20db","password":"PRIVATE","rows":["PRIVATE"],"sqlserverDatabaseDetails":{"compatibilityLevel":150,"recoveryModel":"FULL","password":"PRIVATE"}},{"name":"postgres","project":"demo","instance":"db"}]}`), nil
	})
	// Synthetic permissions isolate behavior; official role membership is
	// verified separately against Google's per-permission table.
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.databases.list": true}
	s := sqlUserSnapshot("db", "db")
	c.CollectViewerSQLDatabases(context.Background(), &s, "demo", "projects/123")
	rows := List(Get(s.Assets[0].Resource.Data, "_gcpbusterSQLDatabases", "items"))
	if calls != 1 || hasCoverage(s, "failed") || len(rows) != 2 || Str(Obj(rows[0])["charset"]) != "utf8mb4" || Get(Obj(rows[0]), "sqlserverDatabaseDetails", "compatibilityLevel") != float64(150) {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("non-metadata field retained")
	}
}

func TestViewerSQLDatabasesMalformedPartial(t *testing.T) {
	for _, bad := range []string{
		`null`, `{"name":"foreign","project":"other","instance":"db"}`, `{"name":"foreign","project":"demo","instance":"other"}`,
		`{"name":42,"project":"demo","instance":"db"}`, `{"name":"x","project":"demo","instance":"db","collation":{}}`,
		`{"name":"x","project":"demo","instance":"db","selfLink":"https://sqladmin.googleapis.com/v1/projects/other/instances/db/databases/x"}`,
		`{"name":"x","project":"demo","instance":"db","sqlserverDatabaseDetails":[]}`,
		`{"name":"x","project":"demo","instance":"db","sqlserverDatabaseDetails":{"compatibilityLevel":1.2}}`,
		`{"name":"x","project":"demo","instance":"db","sqlserverDatabaseDetails":{"compatibilityLevel":2147483648}}`,
		`{"name":"x","project":"demo","instance":"db","sqlserverDatabaseDetails":{"recoveryModel":true}}`,
	} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"items":[{"name":"safe","project":"demo","instance":"db"},`+bad+`]}`), nil
		})
		c.viewerPolicy.permissions = map[string]bool{"cloudsql.databases.list": true}
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLDatabases(context.Background(), &s, "demo", "projects/123")
		e := Obj(s.Assets[0].Resource.Data["_gcpbusterSQLDatabases"])
		if !hasCoverage(s, "failed") || e["status"] != "failed" || len(List(e["items"])) != 1 {
			t.Fatal(bad, s)
		}
	}
}

func TestViewerSQLDatabasesUnexpectedPagination(t *testing.T) {
	for _, body := range []string{`null`, `{"items":{}}`, `{"nextPageToken":"next"}`, `{"nextPageToken":42}`} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) { calls++; return response(200, body), nil })
		c.viewerPolicy.permissions = map[string]bool{"cloudsql.databases.list": true}
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLDatabases(context.Background(), &s, "demo", "projects/123")
		if calls != 1 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerSQLDatabasesDeniedContinues(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.Contains(r.URL.Path, "/first/") {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.databases.list": true}
	s := sqlUserSnapshot("first", "second")
	c.CollectViewerSQLDatabases(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || !hasCoverage(s, "failed") || Str(Get(s.Assets[1].Resource.Data, "_gcpbusterSQLDatabases", "status")) != "completed" {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("upstream error leaked")
	}
}

func TestViewerSQLDatabasesIdentityAndPermission(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	for _, project := range []string{"demo", "../bad"} {
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLDatabases(context.Background(), &s, project, "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.databases.list": true}
	s := sqlUserSnapshot("db")
	s.Assets[0].Resource.Data["project"] = "other"
	c.CollectViewerSQLDatabases(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
