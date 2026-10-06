package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBigtableSubsetScopeProjection(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("PRIVATE_SELECTOR"))
	valid := Object{"rowPrefixes": []any{"", encoded}, "familySubsets": Object{"PRIVATE_FAMILY": Object{"qualifiers": []any{encoded}, "qualifierPrefixes": []any{""}}}}
	got, ok := projectBigtableSubsetScope(valid)
	if !ok || got["all_rows"] != true || got["all_qualifiers_family_count"] != 1 {
		t.Fatal(got, ok)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), encoded) {
		t.Fatal(string(b))
	}
	for _, raw := range []any{nil, false, Object{"rowPrefixes": []any{"", false}}, Object{"rowPrefixes": []any{"%"}}, Object{"familySubsets": Object{"f": false}}, Object{"familySubsets": Object{"f": Object{"qualifierPrefixes": []any{"", false}}}}, Object{"rowPrefixes": []any{strings.Repeat("A", (4<<20)+1)}}} {
		got, ok := projectBigtableSubsetScope(raw)
		if ok || got["complete"] != false {
			t.Fatal(got, ok)
		}
	}
	got, ok = projectBigtableSubsetScope(Object{"rowPrefixes": []any{encoded}, "familySubsets": Object{"f": Object{"qualifiers": []any{""}}}})
	if !ok || got["all_rows"] != false || got["all_qualifiers_family_count"] != 0 {
		t.Fatal(got, ok)
	}
}

func TestViewerBigtableViewsScopedPaginationAndIAM(t *testing.T) {
	parent := "projects/demo/instances/db/tables/data"
	calls, lists := 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "bigtableadmin.googleapis.com" {
			t.Fatal(r.URL)
		}
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			if r.URL.Path != "/v2/"+parent+"/authorizedViews/view:getIamPolicy" || string(b) != `{"options":{"requestedPolicyVersion":3}}` {
				t.Fatal(r.URL, string(b))
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/bigtable.reader","members":["user:reader@example.test"],"condition":{"expression":"true","title":"test"}}]}`), nil
		}
		lists++
		if r.URL.Path != "/v2/"+parent+"/authorizedViews" || r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != viewerBigtableAuthorizedViewFields {
			t.Fatal(r.URL)
		}
		if lists == 1 {
			return response(200, `{"authorizedViews":[{"name":"projects/123/instances/db/tables/data/authorizedViews/view","deletionProtection":false,"subsetView":{"rowPrefixes":[""],"familySubsets":{"PRIVATE_FAMILY":{"qualifierPrefixes":[""]}}},"description":"PRIVATE_DESCRIPTION"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(403, `{"error":{"message":"denied"}}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"bigtable.authorizedViews.list": true, "bigtable.authorizedViews.getIamPolicy": true}
	out := Snapshot{Assets: []Asset{NewAsset("//bigtable.googleapis.com/"+parent, "bigtableadmin.googleapis.com/Table", Object{"name": parent})}}
	c.CollectViewerBigtableAuthorizedViews(context.Background(), &out, "demo", "projects/123")
	if calls != 3 || lists != 2 || len(out.Assets) != 2 || !hasCoverage(out, "failed") || len(List(out.Assets[1].IAM["bindings"])) != 1 {
		t.Fatal(out, calls)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE_") {
		t.Fatal(string(b))
	}
}

func TestViewerBigtableViewsScopeAndPermission(t *testing.T) {
	for _, name := range []string{"projects/foreign/instances/db/tables/data/authorizedViews/v", "projects/demo/instances/db/tables/data/authorizedViews/../x", "projects/demo/instances/db/tables/data/authorizedViews/%2f"} {
		if _, ok := canonicalBigtableViewResource(name, "demo", "projects/123", true); ok {
			t.Fatal(name)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("denied request reached transport")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{}
	parent := "projects/demo/instances/db/tables/data"
	out := Snapshot{Assets: []Asset{NewAsset("//bigtable.googleapis.com/"+parent, "bigtableadmin.googleapis.com/Table", Object{"name": parent})}}
	c.CollectViewerBigtableAuthorizedViews(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") || len(out.Assets) != 1 {
		t.Fatal(out)
	}
}
