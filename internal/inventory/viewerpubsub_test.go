package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func pubSubClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"pubsub.topics.list": true}
	return c
}

func TestViewerPubSubTopicsPaginationProjectionAliases(t *testing.T) {
	calls := 0
	c := pubSubClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "pubsub.googleapis.com" || r.URL.Path != "/v1/projects/demo/topics" || r.URL.Query().Get("fields") != viewerPubSubTopicFields {
			t.Fatal(r.Method, r.URL)
		}
		if calls == 1 {
			return response(200, `{"topics":[{"name":"projects/123/topics/example","kmsKeyName":"projects/demo/locations/global/keyRings/r/cryptoKeys/k","messageStoragePolicy":{"allowedPersistenceRegions":["us-central1"],"enforceInTransit":true,"unknown":"DO_NOT_KEEP"},"schemaSettings":{"schema":"projects/demo/schemas/abc","encoding":"JSON","unknown":"DO_NOT_KEEP"},"messageTransforms":[{"javascriptUdf":{"code":"DO_NOT_KEEP"}}],"ingestionDataSourceSettings":{"password":"DO_NOT_KEEP"},"labels":{"secret":"DO_NOT_KEEP"}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"topics":[{"name":"projects/demo/topics/example"},{"name":"projects/demo/topics/second","satisfiesPzs":true}]}`), nil
	})
	s := Snapshot{}
	c.CollectViewerPubSub(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(calls, s)
	}
	if s.Assets[0].Name != "//pubsub.googleapis.com/projects/demo/topics/example" || s.Assets[0].IAM != nil {
		t.Fatal(s.Assets[0])
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}

func TestViewerPubSubMalformedRetainsValid(t *testing.T) {
	c := pubSubClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"topics":[null,{"name":"projects/other/topics/foreign"},{"name":"projects/demo/topics/a/b"},{"name":"projects/demo/topics/googreserved"},{"name":"projects/demo/topics/bad-schema","schemaSettings":false},{"name":"projects/demo/topics/bad-bool","satisfiesPzs":"true"},{"name":"projects/demo/topics/bad-regions","messageStoragePolicy":{"allowedPersistenceRegions":[false]}},{"name":"projects/demo/topics/valid"}]}`), nil
	})
	s := Snapshot{}
	c.CollectViewerPubSub(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerPubSubDenialsAndLatePage(t *testing.T) {
	for _, mode := range []string{"permission", "server", "late"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := pubSubClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "permission" {
					t.Fatal("unauthorized request")
				}
				if mode == "late" && calls == 1 {
					return response(200, `{"topics":[{"name":"projects/demo/topics/retained"}],"nextPageToken":"next"}`), nil
				}
				return response(403, `{}`), nil
			})
			if mode == "permission" {
				c.viewerPolicy.permissions = map[string]bool{}
			}
			s := Snapshot{}
			c.CollectViewerPubSub(context.Background(), &s, "demo", "projects/123")
			want := 0
			if mode == "late" {
				want = 1
			}
			if len(s.Assets) != want || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerPubSubRejectsInvalidProjectBeforeTransport(t *testing.T) {
	c := pubSubClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerPubSub(context.Background(), &s, "demo/topics/x", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
