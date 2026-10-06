package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveredProjectsActuallyReceiveLogQueries(t *testing.T) {
	queried := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "logging.googleapis.com" {
			var body Object
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			for _, name := range List(body["resourceNames"]) {
				queried[Str(name)]++
			}
			return response(200, `{}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "projects") {
			return response(200, `{"projects":[{"name":"projects/10","projectId":"demo-ten","parent":"folders/2","state":"ACTIVE"}]}`), nil
		}
		// A denied sibling discovery must not discard already discovered projects.
		return response(403, "PRIVATE_ERROR"), nil
	})
	s := Snapshot{}
	scopes := c.ExpandResourceScopes(context.Background(), &s, []string{"folders/2"})
	c.CollectLogs(context.Background(), &s, scopes, logOptions())
	if !reflect.DeepEqual(queried, map[string]int{"folders/2": 1, "projects/10": 1}) || !hasCoverage(s, "failed") {
		t.Fatal(queried, s.Coverage)
	}
}

func TestHierarchyNestedPaginationAndScope(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "cloudresourcemanager.googleapis.com" || r.URL.Query().Get("showDeleted") != "false" {
			t.Fatal(r.URL)
		}
		parent := r.URL.Query().Get("parent")
		switch r.URL.Path + ":" + parent {
		case "/v3/projects:organizations/1":
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"nextPageToken":"next"}`), nil
			}
			return response(200, `{"projects":[{"name":"projects/10","projectId":"demo-ten","parent":"organizations/1","state":"ACTIVE"}]}`), nil
		case "/v3/folders:organizations/1":
			return response(200, `{"folders":[{"name":"folders/2","parent":"organizations/1","state":"ACTIVE"}]}`), nil
		case "/v3/projects:folders/2":
			return response(200, `{"projects":[{"name":"projects/20","projectId":"demo-twenty","parent":"folders/2","state":"ACTIVE"},{"name":"projects/30","parent":"folders/2","state":"DELETE_REQUESTED"}]}`), nil
		case "/v3/folders:folders/2":
			return response(200, `{}`), nil
		default:
			t.Fatal("out-of-scope request", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	got := c.ExpandResourceScopes(context.Background(), &s, []string{"organizations/1", "folders/2", "projects/10"})
	want := []string{"organizations/1", "folders/2", "projects/10", "projects/20"}
	if !reflect.DeepEqual(got, want) || calls != 5 || hasCoverage(s, "failed") {
		t.Fatal(got, calls, s.Coverage)
	}
}

func TestHierarchyFailuresRetainPartialDiscovery(t *testing.T) {
	for _, bad := range []string{`{"projects":{}}`, `{"projects":[{"name":"projects/99","parent":"organizations/elsewhere","state":"ACTIVE"}]}`, `{"projects":[{"name":"projects/99","parent":"folders/2"}]}`, `{"nextPageToken":42}`, `DENIED`} {
		t.Run(bad, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "folders") {
					return response(200, `{}`), nil
				}
				if r.URL.Query().Get("pageToken") == "" {
					return response(200, `{"projects":[{"name":"projects/10","projectId":"demo-ten","parent":"folders/2","state":"ACTIVE"}],"nextPageToken":"next"}`), nil
				}
				if bad == "DENIED" {
					return response(403, "PRIVATE_ERROR"), nil
				}
				return response(200, bad), nil
			})
			s := Snapshot{}
			got := c.ExpandResourceScopes(context.Background(), &s, []string{"folders/2"})
			if !reflect.DeepEqual(got, []string{"folders/2", "projects/10"}) || !hasCoverage(s, "failed") {
				t.Fatal(got, s)
			}
		})
	}
}
