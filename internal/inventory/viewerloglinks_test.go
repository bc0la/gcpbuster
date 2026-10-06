package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerLogLinksPaginationAliasesProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "logging.googleapis.com" || r.URL.Path != "/v2/projects/123/locations/global/buckets/_Default/links" || r.URL.Query().Get("fields") != viewerLogLinkFields {
			t.Fatal(r.Method, r.URL)
		}
		if calls == 1 {
			return response(200, `{"links":[{"name":"projects/demo/locations/global/buckets/_Default/links/linked","lifecycleState":"ACTIVE","bigqueryDataset":{"datasetId":"bigquery.googleapis.com/projects/demo/datasets/linked","extra":"DO_NOT_KEEP"},"description":"DO_NOT_KEEP"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"links":[{"name":"projects/123/locations/global/buckets/_Default/links/linked"},{"name":"projects/123/locations/global/buckets/_Default/links/new","lifecycleState":"CREATING"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"logging.links.list": true}
	snap := logViewSnapshot()
	c.CollectViewerLogLinks(context.Background(), &snap, []string{"projects/demo", "projects/123"})
	if calls != 2 || len(snap.Assets) != 4 || hasCoverage(snap, "failed") {
		t.Fatal(calls, snap)
	}
	if snap.Assets[2].Name != "//logging.googleapis.com/projects/123/locations/global/buckets/_Default/links/linked" {
		t.Fatal(snap)
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}

func TestViewerLogLinksMalformedForeignAndLateFailure(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			return response(403, "DO_NOT_KEEP"), nil
		}
		return response(200, `{"links":[null,{"name":"projects/999/locations/global/buckets/_Default/links/foreign"},{"name":"projects/123/locations/global/buckets/other/links/foreign"},{"name":"projects/123/locations/global/buckets/_Default/links/bad","createTime":"yesterday"},{"name":"projects/123/locations/global/buckets/_Default/links/wrong","bigqueryDataset":{"datasetId":"bigquery.googleapis.com/projects/demo/datasets/other"}},{"name":"projects/123/locations/global/buckets/_Default/links/foreign_project","bigqueryDataset":{"datasetId":"bigquery.googleapis.com/projects/other/datasets/foreign_project"}},{"name":"projects/123/locations/global/buckets/_Default/links/good","lifecycleState":"ACTIVE","bigqueryDataset":{"datasetId":"bigquery.googleapis.com/projects/demo/datasets/good"}}],"nextPageToken":"next"}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"logging.links.list": true}
	snap := logViewSnapshot()
	c.CollectViewerLogLinks(context.Background(), &snap, []string{"projects/demo"})
	if calls != 2 || len(snap.Assets) != 3 || !hasCoverage(snap, "failed") || !strings.HasSuffix(snap.Assets[2].Name, "/good") {
		t.Fatal(calls, snap)
	}
}

func TestViewerLogLinksPermissionDeniedAndScope(t *testing.T) {
	for _, mode := range []string{"permission", "server", "scope", "identity"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode != "server" {
					t.Fatal("unexpected request", r.URL)
				}
				return response(403, "denied"), nil
			})
			c.viewerPolicy.permissions = map[string]bool{"logging.links.list": mode != "permission"}
			snap := logViewSnapshot()
			scopes := []string{"projects/demo"}
			if mode == "scope" {
				scopes = []string{"projects/999"}
				snap.Assets = append(snap.Assets, NewAsset("//cloudresourcemanager.googleapis.com/projects/999", "cloudresourcemanager.googleapis.com/Project", Object{"name": "projects/999", "projectId": "other"}))
			}
			if mode == "identity" {
				snap.Assets[1].Resource.Data["name"] = "projects/123/locations/global/buckets/other"
			}
			before := len(snap.Assets)
			c.CollectViewerLogLinks(context.Background(), &snap, scopes)
			if len(snap.Assets) != before || (mode != "scope" && !hasCoverage(snap, "failed")) || (mode == "server" && calls != 1) {
				t.Fatal(calls, snap)
			}
		})
	}
}
