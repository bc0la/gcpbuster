package inventory

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestViewerComputeSnapshotPaginationPerScope(t *testing.T) {
	for _, scope := range []string{"global", "regions/us-central1"} {
		t.Run(strings.ReplaceAll(scope, "/", "_"), func(t *testing.T) {
			base := "/compute/v1/projects/demo/" + scope + "/snapshots"
			pages, policies := 0, map[string]bool{}
			c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.Host != "compute.googleapis.com" {
					t.Fatal(r.Method, r.URL)
				}
				switch r.URL.Path {
				case base:
					pages++
					if r.URL.Query().Get("fields") != viewerComputeSnapshotFields {
						t.Fatal(r.URL)
					}
					if pages == 1 {
						if r.URL.Query().Get("pageToken") != "" {
							t.Fatal(r.URL)
						}
						return response(200, `{"items":[{"name":"first"}],"nextPageToken":"second-page"}`), nil
					}
					if pages != 2 || r.URL.Query().Get("pageToken") != "second-page" {
						t.Fatal(r.URL)
					}
					return response(200, fmt.Sprintf(`{"items":[{"name":"second","selfLink":"https://www.googleapis.com/compute/v1/projects/123/%s/snapshots/second"}]}`, scope)), nil
				case base + "/first/getIamPolicy", base + "/second/getIamPolicy":
					if policies[r.URL.Path] || r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" || r.URL.Query().Get("fields") != "version,bindings,etag" {
						t.Fatal(r.URL)
					}
					policies[r.URL.Path] = true
					return response(200, `{}`), nil
				default:
					t.Fatal("unexpected request", r.URL)
					return nil, nil
				}
			})
			// Only this list method and its exact policy read are authorized.
			c.viewerPolicy.permissions = map[string]bool{"compute.snapshots.list": true, "compute.snapshots.getIamPolicy": true}
			s := Snapshot{}
			c.viewerComputeDiskList(context.Background(), &s, "demo", "projects/123", scope, "snapshots", "Snapshot")
			if pages != 2 || len(policies) != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") {
				t.Fatal(pages, policies, s)
			}
			for i, name := range []string{"first", "second"} {
				a := s.Assets[i]
				if a.Name != "//compute.googleapis.com/projects/demo/"+scope+"/snapshots/"+name || a.Type != "compute.googleapis.com/Snapshot" || a.IAM == nil || len(a.IAM) != 0 {
					t.Fatal(a)
				}
			}
		})
	}
}
