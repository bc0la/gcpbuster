package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerFilestoreAggregateProjectionPagination(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/projects/demo/locations/-/instances" || r.URL.Query().Get("fields") != viewerFilestoreFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"instances":[{"name":"projects/123/locations/us-central1-a/instances/fs","state":"READY","description":"SECRET_SENTINEL","directoryServices":{"password":"SECRET_SENTINEL"},"fileShares":[{"name":"SECRET_SENTINEL","nfsExportOptions":[{"ipRanges":["0.0.0.0/0"],"accessMode":"READ_WRITE","squashMode":"NO_ROOT_SQUASH"}]}]}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"instances":[{"name":"projects/demo/locations/us-east1-b/instances/fs-two"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"file.instances.list": true}
	s := Snapshot{}
	c.CollectViewerFilestore(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") || hasCoverage(s, "partial") {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal(string(b))
	}
}

func TestViewerFilestoreScopeMalformedAndPartial(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"unreachable":["us-east1"],"instances":[{"name":"projects/foreign/locations/us-east1-b/instances/fs"},{"name":"projects/demo/locations/us-east1-b/instances/fs","state":"READY|REPAIRING","fileShares":[{"nfsExportOptions":[{"accessMode":"READ_WRITE","squashMode":"NO_ROOT_SQUASH","ipRanges":["::/0"]},{"accessMode":"READ_ONLY","squashMode":"ROOT_SQUASH","anonUid":"65534","ipRanges":["10.1.2.3","10.2.3.4/24"]}]}]}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"file.instances.list": true}
	s := Snapshot{}
	c.CollectViewerFilestore(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || (!hasCoverage(s, "partial") && !hasCoverage(s, "failed")) {
		t.Fatal(s)
	}
	d := s.Assets[0].Resource.Data
	if _, exists := d["state"]; exists {
		t.Fatal(d)
	}
	opts := List(Obj(List(d["fileShares"])[0])["nfsExportOptions"])
	if len(opts) != 2 || len(Obj(opts[0])) != 0 || Str(Obj(opts[1])["anonUid"]) != "65534" {
		t.Fatal(d)
	}
}

func TestViewerFilestoreGuardAndRoleGate(t *testing.T) {
	endpoint := "https://file.googleapis.com/v1/projects/demo/locations/-/instances"
	q := url.Values{"fields": {viewerFilestoreFields}, "pageSize": {"100"}}
	if perms, e := viewerRequestPermissions("GET", endpoint, q); e != nil || len(perms) != 1 || perms[0] != "file.instances.list" {
		t.Fatal(perms, e)
	}
	for _, query := range []url.Values{{"fields": {"*"}, "pageSize": {"100"}}, {"fields": {viewerFilestoreFields}, "pageSize": {"100"}, "filter": {"x"}}, {"fields": {viewerFilestoreFields}, "pageSize": {"100", "100"}}} {
		if _, e := viewerRequestPermissions("GET", endpoint, query); e == nil {
			t.Fatal(query)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("blocked request reached transport")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{}
	s := Snapshot{}
	c.CollectViewerFilestore(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{"file.instances.list": true, "file.instances.get": true, "file.instances.restore": true, "file.backups.list": true}
	for _, path := range []string{"/v1/projects/demo/locations/us-east1-b/instances/fs", "/v1/projects/demo/locations/-/backups", "/v1/projects/demo/locations/us-east1-b/instances/fs:restore"} {
		if _, e := c.get(context.Background(), "https://file.googleapis.com"+path, q); e == nil {
			t.Fatal(path)
		}
	}
	if _, e := viewerRequestPermissions("POST", endpoint, q); e == nil {
		t.Fatal("mutation allowed")
	}
}

func TestViewerFilestoreRetainsEarlierPageOnFailure(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"instances":[{"name":"projects/demo/locations/us-central1-a/instances/fs"}],"nextPageToken":"next","unreachable":["us-east1"]}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal("unreachable marker prevented continued pagination")
		}
		return response(403, `{"error":{"message":"denied"}}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"file.instances.list": true}
	out := Snapshot{}
	c.CollectViewerFilestore(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 1 || !hasCoverage(out, "failed") {
		t.Fatal(out, calls)
	}
}
