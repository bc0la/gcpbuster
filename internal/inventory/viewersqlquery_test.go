package inventory

import (
	"net/url"
	"testing"
)

func TestViewerSQLMetadataProjectionGuard(t *testing.T) {
	for _, tc := range []struct{ path, fields, permission string }{
		{"users", viewerSQLUserFields, "cloudsql.users.list"},
		{"databases", viewerSQLDatabaseFields, "cloudsql.databases.list"},
		{"backupRuns", viewerSQLBackupListFields, "cloudsql.backupRuns.list"},
		{"backupRuns/123", viewerSQLBackupFields, "cloudsql.backupRuns.get"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			endpoint := "https://sqladmin.googleapis.com/v1/projects/demo/instances/db/" + tc.path
			query := url.Values{"fields": {tc.fields}}
			if tc.path == "backupRuns" {
				query.Set("maxResults", "100")
				query.Set("pageToken", "next")
			}
			permissions, err := viewerRequestPermissions("GET", endpoint, query)
			if err != nil || len(permissions) != 1 || permissions[0] != tc.permission {
				t.Fatal(permissions, err)
			}
			for _, mutation := range []func(url.Values){
				func(q url.Values) { q.Set("fields", tc.fields+",password") },
				func(q url.Values) { q.Del("fields") },
				func(q url.Values) { q.Add("fields", tc.fields) },
				func(q url.Values) { q.Set("unreviewed", "value") },
			} {
				bad := url.Values{}
				for key, values := range query {
					bad[key] = append([]string(nil), values...)
				}
				mutation(bad)
				if _, err := viewerRequestPermissions("GET", endpoint, bad); err == nil {
					t.Fatal("accepted", bad)
				}
			}
		})
	}
}
