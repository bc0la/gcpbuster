package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func sqlUserSnapshot(names ...string) Snapshot {
	var s Snapshot
	for _, name := range names {
		s.Assets = append(s.Assets, NewAsset("//cloudsql.googleapis.com/projects/demo/instances/"+name, "sqladmin.googleapis.com/Instance", Object{"name": name, "project": "demo"}))
	}
	return s
}

func TestViewerSQLUsersProjectionAndDuplicateParents(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "sqladmin.googleapis.com" || r.URL.Path != "/v1/projects/demo/instances/db/users" || r.URL.Query().Get("fields") != viewerSQLUserFields || len(r.URL.Query()) != 1 {
			t.Fatal(r.URL)
		}
		return response(200, `{"items":[{"name":"root","project":"demo","instance":"db","host":"%","type":"BUILT_IN","databaseRoles":["read"],"serverRoles":["public"],"password":"PRIVATE","hash":"PRIVATE","passwordPolicy":{"password":"PRIVATE"}},{"name":"","host":"localhost","project":"demo","instance":"db"}]}`), nil
	})
	// Synthetic permission fixture tests behavior, not actual role membership.
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.users.list": true}
	s := sqlUserSnapshot("db", "db")
	c.CollectViewerSQLUsers(context.Background(), &s, "demo", "projects/123")
	if calls != 1 || hasCoverage(s, "failed") || len(List(Get(s.Assets[0].Resource.Data, "_gcpbusterSQLUsers", "items"))) != 2 {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(viewerSQLUserFields, "password") {
		t.Fatal("credential field retained or requested")
	}
}

func TestViewerSQLUsersMalformedRowsRetainSafeEvidence(t *testing.T) {
	for _, malformed := range []string{`null`, `{"name":"foreign","project":"other","instance":"db"}`, `{"name":"foreign","project":"demo","instance":"other"}`, `{"name":32,"project":"demo","instance":"db"}`, `{"name":"bad","project":"demo","instance":"db","host":{}}`, `{"name":"bad","project":"demo","instance":"db","databaseRoles":[{}]}`, `{"name":"bad","project":"demo","instance":"db","serverRoles":{}}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"items":[{"name":"safe","project":"demo","instance":"db"},`+malformed+`]}`), nil
		})
		c.viewerPolicy.permissions = map[string]bool{"cloudsql.users.list": true}
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLUsers(context.Background(), &s, "demo", "projects/123")
		e := Obj(s.Assets[0].Resource.Data["_gcpbusterSQLUsers"])
		if !hasCoverage(s, "failed") || e["status"] != "failed" || len(List(e["items"])) != 1 {
			t.Fatal(malformed, s)
		}
	}
}

func TestViewerSQLUsersUnpaginatedAndMalformedResponse(t *testing.T) {
	for _, body := range []string{`null`, `{"items":{}}`, `{"nextPageToken":"unexpected"}`, `{"nextPageToken":123}`} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) { calls++; return response(200, body), nil })
		c.viewerPolicy.permissions = map[string]bool{"cloudsql.users.list": true}
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLUsers(context.Background(), &s, "demo", "projects/123")
		if calls != 1 || !hasCoverage(s, "failed") {
			t.Fatal(body, s, calls)
		}
	}
}

func TestViewerSQLUsersFailureContinuesOtherInstances(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.Contains(r.URL.Path, "/first/") {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.users.list": true}
	s := sqlUserSnapshot("first", "second")
	c.CollectViewerSQLUsers(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || !hasCoverage(s, "failed") || Str(Get(s.Assets[1].Resource.Data, "_gcpbusterSQLUsers", "status")) != "completed" {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("upstream error leaked")
	}
}

func TestViewerSQLUsersScopeAndMissingPermission(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	for _, project := range []string{"demo", "../bad"} {
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLUsers(context.Background(), &s, project, "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.users.list": true}
	s := sqlUserSnapshot("db")
	s.Assets[0].Resource.Data["project"] = "other"
	c.CollectViewerSQLUsers(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
