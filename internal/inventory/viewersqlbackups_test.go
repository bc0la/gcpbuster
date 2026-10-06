package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func sqlBackupClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.backupRuns.list": true, "cloudsql.backupRuns.get": true}
	return c
}

func TestViewerSQLBackupsPaginationProjectionAndDuplicateParents(t *testing.T) {
	calls := 0
	c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "sqladmin.googleapis.com" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/instances/db/backupRuns":
			if r.URL.Query().Get("fields") != viewerSQLBackupListFields || r.URL.Query().Get("maxResults") != "100" {
				t.Fatal(r.URL)
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"items":[{"id":"123","instance":"db","status":"SUCCESSFUL","type":"AUTOMATED","backupKind":"PHYSICAL","location":"us","startTime":"2026-01-01T00:00:00Z","endTime":"2026-01-01T01:00:00Z","error":{"message":"PRIVATE"},"description":"PRIVATE","selfLink":"https://never-follow.invalid/PRIVATE","contents":"PRIVATE"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"items":[{"id":"123","instance":"db","status":"SUCCESSFUL"},{"id":"124","instance":"db","status":"SUCCESSFUL"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := sqlUserSnapshot("db", "db")
	c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
	items := List(Get(s.Assets[0].Resource.Data, "_gcpbusterSQLBackups", "items"))
	if calls != 2 || hasCoverage(s, "failed") || len(items) != 2 || Str(Obj(items[0])["status"]) != "SUCCESSFUL" {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal(string(b))
	}
}

func TestViewerSQLBackupsMalformedMetadataContinues(t *testing.T) {
	for _, body := range []string{`{"id":"1","instance":"db"}`, `{"id":"1","instance":"db","status":42}`, `{"id":"1","instance":"db","status":"SUCCESSFUL","startTime":"bad"}`, `{"id":"1","instance":"db","status":"SUCCESSFUL","location":{}}`} {
		t.Run(body, func(t *testing.T) {
			c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/backupRuns") {
					t.Fatal("redundant detail request", r.URL)
				}
				return response(200, `{"items":[`+body+`,{"id":"2","instance":"db","status":"FAILED"}]}`), nil
			})
			s := sqlUserSnapshot("db")
			c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
			items := List(Get(s.Assets[0].Resource.Data, "_gcpbusterSQLBackups", "items"))
			if !hasCoverage(s, "failed") || len(items) != 2 || Str(Obj(items[0])["metadataStatus"]) != "failed" || Str(Obj(items[1])["metadataStatus"]) != "completed" {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerSQLBackupsListValidationAndPaginationFailure(t *testing.T) {
	for _, body := range []string{`{"items":{}}`, `{"items":[null]}`, `{"items":[{"id":"../bad","instance":"db"}]}`, `{"items":[{"id":123,"instance":"db"}]}`, `{"items":[{"id":"9223372036854775808","instance":"db"}]}`, `{"items":[{"id":"1","instance":"other"}]}`, `{"nextPageToken":42}`} {
		c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/backupRuns") {
				t.Fatal(r.URL)
			}
			return response(200, body), nil
		})
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerSQLBackupsPermissionsAndServerDenial(t *testing.T) {
	for _, permission := range []string{"cloudsql.backupRuns.list", "cloudsql.backupRuns.get", "server-denial"} {
		calls := 0
		c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if permission == "server-denial" {
				return response(403, "PRIVATE"), nil
			}
			return response(200, `{"items":[{"id":"1","instance":"db","status":"SUCCESSFUL"}]}`), nil
		})
		delete(c.viewerPolicy.permissions, permission)
		s := sqlUserSnapshot("db")
		c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
		want := map[string]int{"cloudsql.backupRuns.list": 0, "cloudsql.backupRuns.get": 1, "server-denial": 1}[permission]
		if calls != want || hasCoverage(s, "failed") != (permission != "cloudsql.backupRuns.get") {
			t.Fatal(permission, s, calls)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal(string(b))
		}
	}
}

func TestViewerSQLBackupsBoundAndScope(t *testing.T) {
	rows := []any{}
	for i := 1; i <= viewerSQLBackupLimit+1; i++ {
		rows = append(rows, Object{"id": strconv.Itoa(i), "instance": "db", "status": "SUCCESSFUL"})
	}
	body, _ := json.Marshal(Object{"items": rows})
	c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/backupRuns") {
			t.Fatal("redundant detail reached network")
		}
		return response(200, string(body)), nil
	})
	delete(c.viewerPolicy.permissions, "cloudsql.backupRuns.get")
	s := sqlUserSnapshot("db")
	c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(List(Get(s.Assets[0].Resource.Data, "_gcpbusterSQLBackups", "items"))) != viewerSQLBackupLimit {
		t.Fatal("unbounded backup inventory")
	}
	c = sqlBackupClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("out of scope request"); return nil, nil })
	s = sqlUserSnapshot("db")
	s.Assets[0].Resource.Data["project"] = "other"
	c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerSQLBackupsLatePageFailureKeepsEvidenceAndOtherInstance(t *testing.T) {
	c := sqlBackupClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/second/") {
			return response(200, `{}`), nil
		}
		if r.URL.Query().Get("pageToken") != "" {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{"items":[{"id":"1","instance":"first","status":"SUCCESSFUL"}],"nextPageToken":"next"}`), nil
	})
	s := sqlUserSnapshot("first", "second")
	c.CollectViewerSQLBackups(context.Background(), &s, "demo", "projects/123")
	first := Obj(s.Assets[0].Resource.Data["_gcpbusterSQLBackups"])
	second := Obj(s.Assets[1].Resource.Data["_gcpbusterSQLBackups"])
	if !hasCoverage(s, "failed") || first["status"] != "failed" || len(List(first["items"])) != 1 || second["status"] != "completed" {
		t.Fatal(s)
	}
}
