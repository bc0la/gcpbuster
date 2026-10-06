package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerFirestoreMetadataProjectionAndScope(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || len(r.URL.Query()) != 1 {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/databases":
			return response(200, `{"databases":[{"name":"projects/123/databases/(default)","deleteProtectionState":"DELETE_PROTECTION_DISABLED","pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_DISABLED","versionRetentionPeriod":"3600s","locationId":"nam5","documents":{"secret":"DO_NOT_RETAIN"}},{"name":"projects/foreign/databases/no"}],"unreachable":["region"]}`), nil
		case "/v1/projects/demo/locations/-/backups":
			return response(200, `{"backups":[{"name":"projects/123/locations/nam5/backups/bk1","database":"projects/demo/databases/(default)","state":"READY","snapshotTime":"2026-01-01T00:00:00Z","expireTime":"2026-02-01T00:00:00Z","stats":{"secret":"DO_NOT_RETAIN"}}]}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"datastore.databases.list": true, "datastore.backups.list": true}
	s := Snapshot{}
	c.CollectViewerFirestore(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_RETAIN") {
		t.Fatal(string(b))
	}
	if s.Assets[0].Name != "//firestore.googleapis.com/projects/demo/databases/(default)" {
		t.Fatal(s)
	}
	d, ok := projectViewerFirestore(Object{"deleteProtectionState": "DELETE_PROTECTION_DISABLED|DELETE_PROTECTION_ENABLED", "pointInTimeRecoveryEnablement": nil, "versionRetentionPeriod": "SECRET"}, "projects/demo/databases/db", "Database", "demo", "projects/123")
	if ok || len(d) != 1 {
		t.Fatal(d, ok)
	}
}

func TestViewerFirestoreStrictGuardAndRoleGate(t *testing.T) {
	base := "https://firestore.googleapis.com/v1/projects/demo/"
	for _, tc := range []struct{ path, fields, permission string }{{"databases", viewerFirestoreDatabaseFields, "datastore.databases.list"}, {"locations/-/backups", viewerFirestoreBackupFields, "datastore.backups.list"}} {
		q := url.Values{"fields": {tc.fields}}
		p, e := viewerRequestPermissions("GET", base+tc.path, q)
		if e != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, e)
		}
		for _, key := range []string{"pageSize", "pageToken", "showDeleted", "filter"} {
			q := url.Values{"fields": {tc.fields}, key: {"x"}}
			if _, e := viewerRequestPermissions("GET", base+tc.path, q); e == nil {
				t.Fatal(q)
			}
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("blocked reached transport"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{"datastore.entities.get": true, "datastore.entities.list": true, "datastore.databases.export": true, "datastore.databases.clone": true, "datastore.userCreds.list": true}
	for _, path := range []string{"databases/(default)/documents", "databases/(default)/documents:runQuery", "databases/(default):exportDocuments", "databases/(default):clone", "databases/(default)/userCreds", "databases/(default):getIamPolicy"} {
		if _, e := c.get(context.Background(), base+path, url.Values{"fields": {viewerFirestoreDatabaseFields}}); e == nil {
			t.Fatal(path)
		}
	}
	s := Snapshot{}
	c.CollectViewerFirestore(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
