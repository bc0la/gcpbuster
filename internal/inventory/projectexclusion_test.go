package inventory

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSystemProjectHierarchyExclusionAndOverride(t *testing.T) {
	for _, include := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "include"}[include], func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v3/projects":
					return response(200, `{"projects":[{"name":"projects/123","projectId":"sys-script","parent":"organizations/9","state":"ACTIVE"},{"name":"projects/456","projectId":"demo-app","parent":"organizations/9","state":"ACTIVE"}]}`), nil
				case "/v3/folders":
					return response(200, `{}`), nil
				default:
					t.Fatalf("unexpected metadata/service request %s", r.URL)
					return nil, nil
				}
			})
			c.IncludeSystemProjects = include
			s := Snapshot{}
			got := c.ExpandResourceScopes(context.Background(), &s, []string{"organizations/9"})
			want := []string{"organizations/9", "projects/456"}
			if include {
				want = []string{"organizations/9", "projects/123", "projects/456"}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scopes %v", got)
			}
			if !include && !hasCoverage(s, "skipped") {
				t.Fatal("exclusion not reported")
			}
		})
	}
}

func TestSystemProjectExplicitIDsAndNumericScopes(t *testing.T) {
	for _, scope := range []string{"projects/sys-script", "projects/123"} {
		t.Run(scope, func(t *testing.T) {
			calls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/v3/projects/123" || r.URL.Query().Get("fields") != "name,projectId" {
					t.Fatalf("unexpected request: %s", r.URL)
				}
				return response(200, `{"name":"projects/123","projectId":"sys-script"}`), nil
			})
			s := Snapshot{}
			got := c.ExpandResourceScopes(context.Background(), &s, []string{scope})
			if len(got) != 0 || !hasCoverage(s, "skipped") {
				t.Fatalf("system project not excluded: %v %+v", got, s.Coverage)
			}
			wantCalls := 1
			if strings.HasPrefix(scope, "projects/sys-") {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("metadata calls %d", calls)
			}
		})
	}
}

func TestSystemProjectAncestorExclusionBeforePolicies(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v3/projects/123" {
			t.Fatalf("policy or ancestor read for excluded project: %s", r.URL)
		}
		return response(200, `{"name":"projects/123","projectId":"sys-script","parent":"organizations/9"}`), nil
	})
	s := Snapshot{}
	c.CollectAncestorIAM(context.Background(), &s, []string{"projects/sys-script", "projects/123"})
	if !hasCoverage(s, "skipped") || len(s.Assets) != 0 {
		t.Fatalf("excluded ancestor read retained: %+v", s)
	}
}
