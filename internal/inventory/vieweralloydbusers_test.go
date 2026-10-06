package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerAlloyDBUsersScopedProjection(t *testing.T) {
	calls := 0
	parent := "projects/demo/locations/us-central1/clusters/db"
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/"+parent+"/users" || r.URL.Query().Get("fields") != viewerAlloyDBUserFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"users":[{"name":"projects/123/locations/us-central1/cluster/db/users/PRIVATE_USER","userType":"ALLOYDB_IAM_USER","password":"PRIVATE_PASSWORD","databaseRoles":["alloydbsuperuser","PRIVATE_ROLE"]}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"alloydb.users.list": true}
	out := Snapshot{Assets: []Asset{NewAsset("//alloydb.googleapis.com/"+parent, "alloydb.googleapis.com/Cluster", Object{"name": parent})}}
	c.CollectViewerAlloyDBUsers(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 2 || hasCoverage(out, "failed") {
		t.Fatal(out, calls)
	}
	b, _ := json.Marshal(out)
	for _, secret := range []string{"PRIVATE_USER", "PRIVATE_PASSWORD", "PRIVATE_ROLE"} {
		if strings.Contains(string(b), secret) {
			t.Fatal(string(b))
		}
	}
	if len(List(out.Assets[1].Resource.Data["databaseRoles"])) != 1 {
		t.Fatal(out)
	}
}

func TestAlloyDBUserScopeAndMalformed(t *testing.T) {
	parent := "projects/demo/locations/us-central1/clusters/db"
	for _, name := range []string{"projects/foreign/locations/us-central1/clusters/db/users/u", parent + "/users/", parent + "/users/../../foreign"} {
		if got, err := projectViewerAlloyDBUser(Object{"name": name}, parent, "demo", "projects/123"); got != nil || err == nil {
			t.Fatal(got, err)
		}
	}
	got, err := projectViewerAlloyDBUser(Object{"name": parent + "/users/u", "userType": "BAD", "databaseRoles": []any{"alloydbsuperuser", false}}, parent, "demo", "projects/123")
	if got == nil || err == nil || len(List(got["databaseRoles"])) != 1 {
		t.Fatal(got, err)
	}
}

func TestViewerAlloyDBUsersPermissionAndPartialPages(t *testing.T) {
	parent := "projects/demo/locations/us-central1/clusters/db"
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "partial"}[allowed], func(t *testing.T) {
			calls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if !allowed {
					t.Fatal("missing permission reached transport")
				}
				if calls == 1 {
					return response(200, `{"users":[{"name":"`+parent+`/users/u","databaseRoles":["alloydbsuperuser"]}],"nextPageToken":"next","unreachable":["us-east1"]}`), nil
				}
				if r.URL.Query().Get("pageToken") != "next" {
					t.Fatal("pagination token lost")
				}
				return response(403, `{"error":{"message":"denied"}}`), nil
			})
			c.viewerPolicy.permissions = map[string]bool{"alloydb.users.list": allowed}
			out := Snapshot{Assets: []Asset{NewAsset("//alloydb.googleapis.com/"+parent, "alloydb.googleapis.com/Cluster", Object{"name": parent})}}
			c.CollectViewerAlloyDBUsers(context.Background(), &out, "demo", "projects/123")
			if !hasCoverage(out, "failed") {
				// A failed later page with retained evidence is classified partial.
				if !allowed || !hasCoverage(out, "partial") {
					t.Fatal(out.Coverage)
				}
			}
			wantAssets, wantCalls := 1, 0
			if allowed {
				wantAssets, wantCalls = 2, 2
			}
			if len(out.Assets) != wantAssets || calls != wantCalls {
				t.Fatal(out, calls)
			}
		})
	}
}
