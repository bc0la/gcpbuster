package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerPubSubSnapshotsPaginationProjectionAliases(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "pubsub.googleapis.com" || r.URL.Path != "/v1/projects/demo/snapshots" || r.URL.Query().Get("fields") != viewerPubSubSnapshotFields {
			t.Fatal(r.Method, r.URL)
		}
		if calls == 1 {
			return response(200, `{"snapshots":[{"name":"projects/123/snapshots/snap","topic":"projects/other/topics/events","expireTime":"2099-01-01T00:00:00Z","labels":{"secret":"DO_NOT_KEEP"},"messages":["DO_NOT_KEEP"]}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"snapshots":[{"name":"projects/demo/snapshots/snap"},{"name":"projects/demo/snapshots/another"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"pubsub.snapshots.list": true}
	snap := Snapshot{}
	c.CollectViewerPubSubSnapshots(context.Background(), &snap, "demo", "projects/123")
	if calls != 2 || len(snap.Assets) != 2 || hasCoverage(snap, "failed") || snap.Assets[0].Name != "//pubsub.googleapis.com/projects/demo/snapshots/snap" {
		t.Fatal(calls, snap)
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}
func TestViewerPubSubSnapshotsMalformedPartialAndLatePage(t *testing.T) {
	for _, late := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 2 {
				if late {
					return response(403, "denied"), nil
				}
				return response(200, `{"snapshots":[{"name":"projects/demo/snapshots/last"}]}`), nil
			}
			return response(200, `{"snapshots":[null,{"name":"projects/999/snapshots/foreign"},{"name":"projects/demo/snapshots/googbad"},{"name":"projects/demo/snapshots/bad","expireTime":false},{"name":"projects/demo/snapshots/bad2","topic":"https://evil.invalid/"},{"name":"projects/demo/snapshots/valid"}],"unreachable":["region"],"nextPageToken":"next"}`), nil
		})
		c.viewerPolicy.permissions = map[string]bool{"pubsub.snapshots.list": true}
		snap := Snapshot{}
		c.CollectViewerPubSubSnapshots(context.Background(), &snap, "demo", "projects/123")
		want := 2
		if late {
			want = 1
		}
		if calls != 2 || len(snap.Assets) != want || !hasCoverage(snap, "failed") {
			t.Fatal(late, calls, snap)
		}
	}
}
func TestViewerPubSubSnapshotsDeniedAndInvalidScope(t *testing.T) {
	for _, mode := range []string{"permission", "server", "scope"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode != "server" {
					t.Fatal(r.URL)
				}
				return response(403, "denied"), nil
			})
			c.viewerPolicy.permissions = map[string]bool{"pubsub.snapshots.list": mode != "permission"}
			snap := Snapshot{}
			project := "demo"
			if mode == "scope" {
				project = "../foreign"
			}
			c.CollectViewerPubSubSnapshots(context.Background(), &snap, project, "projects/123")
			if len(snap.Assets) != 0 || !hasCoverage(snap, "failed") || (mode == "server" && calls != 1) {
				t.Fatal(calls, snap)
			}
		})
	}
}
