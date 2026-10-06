package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func schemaClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"pubsub.schemas.list": true, "pubsub.schemas.listRevisions": true}
	return c
}

func TestViewerPubSubSchemasBasicPaginationProjection(t *testing.T) {
	lists, revisions := 0, 0
	c := schemaClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "pubsub.googleapis.com" || r.URL.Query().Get("view") != "BASIC" || len(r.URL.Query()["view"]) != 1 || r.URL.Query().Get("fields") != viewerPubSubSchemaFields {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/schemas":
			lists++
			if lists == 1 {
				return response(200, `{"schemas":[{"name":"projects/123/schemas/example","type":"AVRO","revisionId":"a1","definition":"DO_NOT_KEEP"}],"nextPageToken":"more"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "more" {
				t.Fatal(r.URL)
			}
			return response(200, `{"schemas":[{"name":"projects/demo/schemas/example","type":"AVRO"}]}`), nil
		case "/v1/projects/demo/schemas/example:listRevisions":
			revisions++
			if revisions == 1 {
				return response(200, `{"schemas":[{"name":"projects/123/schemas/example","type":"AVRO","revisionId":"a1","revisionCreateTime":"2026-01-01T00:00:00Z","definition":"DO_NOT_KEEP"}],"nextPageToken":"rev"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "rev" {
				t.Fatal(r.URL)
			}
			return response(200, `{"schemas":[{"name":"projects/demo/schemas/example@a1","revisionId":"a1"},{"name":"projects/demo/schemas/example@b2","revisionId":"b2","type":"AVRO"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerPubSubSchemas(context.Background(), &s, "demo", "projects/123")
	if lists != 2 || revisions != 2 || len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(lists, revisions, s)
	}
	if s.Assets[2].Type != PubSubSchemaRevisionType || s.Assets[2].Name != "//pubsub.googleapis.com/projects/demo/schemas/example@b2" {
		t.Fatal(s.Assets)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") || strings.Contains(string(b), "definition") {
		t.Fatal(string(b))
	}
}

func TestViewerPubSubSchemasMalformedRetainsValid(t *testing.T) {
	c := schemaClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/schemas") {
			return response(200, `{"schemas":[null,{"name":"projects/other/schemas/foreign"},{"name":"projects/demo/schemas/example","type":"AVRO"},{"name":"projects/demo/schemas/example@bad"},{"name":"projects/demo/schemas/badtype","type":false}]}`), nil
		}
		return response(200, `{"schemas":[{"name":"projects/demo/schemas/example"},{"name":"projects/demo/schemas/different","revisionId":"a1"},{"name":"projects/demo/schemas/example@wrong","revisionId":"a1"},{"name":"projects/demo/schemas/example","revisionId":"bad/time"},{"name":"projects/demo/schemas/example","revisionId":"badtime","revisionCreateTime":"bad"},{"name":"projects/demo/schemas/example","revisionId":"valid"}]}`), nil
	})
	s := Snapshot{}
	c.CollectViewerPubSubSchemas(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerPubSubSchemasDenialsPreserveMetadata(t *testing.T) {
	for _, mode := range []string{"list-permission", "revision-permission", "server", "late-list", "late-revision"} {
		t.Run(mode, func(t *testing.T) {
			c := schemaClient(t, func(r *http.Request) (*http.Response, error) {
				if mode == "list-permission" {
					t.Fatal("unauthorized list")
				}
				if mode == "server" || r.URL.Query().Get("pageToken") != "" {
					return response(403, `{}`), nil
				}
				next := ""
				if mode == "late-list" && strings.HasSuffix(r.URL.Path, "/schemas") || mode == "late-revision" && strings.HasSuffix(r.URL.Path, ":listRevisions") {
					next = `,"nextPageToken":"late"`
				}
				if !strings.HasSuffix(r.URL.Path, "/schemas") && mode == "revision-permission" {
					t.Fatal("unauthorized revisions")
				}
				return response(200, `{"schemas":[{"name":"projects/demo/schemas/example","type":"AVRO","revisionId":"a1"}]`+next+`}`), nil
			})
			if mode == "list-permission" {
				delete(c.viewerPolicy.permissions, "pubsub.schemas.list")
			}
			if mode == "revision-permission" {
				delete(c.viewerPolicy.permissions, "pubsub.schemas.listRevisions")
			}
			s := Snapshot{}
			c.CollectViewerPubSubSchemas(context.Background(), &s, "demo", "projects/123")
			want := 2
			if mode == "list-permission" || mode == "server" {
				want = 0
			}
			if mode == "revision-permission" {
				want = 1
			}
			if len(s.Assets) != want || !hasCoverage(s, "failed") {
				t.Fatal(mode, s)
			}
		})
	}
}

func TestViewerPubSubSchemasInvalidProjectNoTransport(t *testing.T) {
	c := schemaClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerPubSubSchemas(context.Background(), &s, "demo/schemas/x", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerPubSubSchemasEscapesIdentifierAndRetainsUnreachablePages(t *testing.T) {
	lists, revisions := 0, 0
	c := schemaClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/schemas") {
			lists++
			if lists == 1 {
				return response(200, `{"schemas":[{"name":"projects/demo/schemas/special%+name","type":"AVRO"}],"unreachable":["us-central1"],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{}`), nil
		}
		revisions++
		if r.URL.EscapedPath() != "/v1/projects/demo/schemas/special%25+name:listRevisions" {
			t.Fatal(r.URL.EscapedPath())
		}
		return response(200, `{"schemas":[{"name":"projects/demo/schemas/special%+name","revisionId":"a1"}]}`), nil
	})
	s := Snapshot{}
	c.CollectViewerPubSubSchemas(context.Background(), &s, "demo", "projects/123")
	if lists != 2 || revisions != 1 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(lists, revisions, s)
	}
}
