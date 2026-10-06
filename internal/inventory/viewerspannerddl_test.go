package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func spannerDDLAsset(name, dialect string) Asset {
	return NewAsset("//spanner.googleapis.com/"+name, "spanner.googleapis.com/Database", Object{"name": name, "databaseDialect": dialect})
}

func TestViewerSpannerDDLScopedRedaction(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "spanner.googleapis.com" || r.URL.Path != "/v1/projects/demo/instances/db/databases/data/ddl" || r.URL.Query().Get("fields") != "statements" {
			t.Fatal(r.URL)
		}
		return response(200, `{"statements":["CREATE CHANGE STREAM PRIVATE_NAME FOR ALL OPTIONS (retention_period = '7d')","CREATE TABLE PRIVATE_TABLE (id INT64 NOT NULL) PRIMARY KEY(id)"],"protoDescriptors":"PRIVATE_PROTO"}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"spanner.databases.getDdl": true}
	out := Snapshot{Assets: []Asset{spannerDDLAsset("projects/123/instances/db/databases/data", "GOOGLE_STANDARD_SQL")}}
	c.CollectViewerSpannerDDL(context.Background(), &out, "demo", "projects/123")
	if calls != 1 || hasCoverage(out, "failed") || len(List(out.Assets[0].Resource.Data["_gcpbusterChangeStreams"])) != 1 {
		t.Fatal(out, calls)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "retention_period") {
		t.Fatal(string(b))
	}
}

func TestViewerSpannerDDLUnknownAndConflictingParents(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported parent reached transport")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"spanner.databases.getDdl": true}
	out := Snapshot{Assets: []Asset{
		spannerDDLAsset("projects/demo/instances/db/databases/data", "GOOGLE_STANDARD_SQL"),
		spannerDDLAsset("projects/123/instances/db/databases/data", "POSTGRESQL"),
		spannerDDLAsset("projects/demo/instances/db/databases/unknown", ""),
		spannerDDLAsset("projects/foreign/instances/db/databases/data", "GOOGLE_STANDARD_SQL"),
	}}
	c.CollectViewerSpannerDDL(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	for _, a := range out.Assets {
		if len(List(a.Resource.Data["_gcpbusterChangeStreams"])) != 0 {
			t.Fatal(a)
		}
	}
}

func TestViewerSpannerDDLPermissionAndMalformed(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			calls++
			if !allowed {
				t.Fatal("permission denial reached transport")
			}
			return response(200, `{"statements":false}`), nil
		})
		c.viewerPolicy.permissions = map[string]bool{"spanner.databases.getDdl": allowed}
		out := Snapshot{Assets: []Asset{spannerDDLAsset("projects/demo/instances/db/databases/data", "GOOGLE_STANDARD_SQL")}}
		c.CollectViewerSpannerDDL(context.Background(), &out, "demo", "projects/123")
		if !hasCoverage(out, "failed") || len(List(out.Assets[0].Resource.Data["_gcpbusterChangeStreams"])) != 0 || (!allowed && calls != 0) {
			t.Fatal(out, calls)
		}
	}
}
