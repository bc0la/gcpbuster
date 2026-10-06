package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func logViewSnapshot() Snapshot {
	return Snapshot{Assets: []Asset{
		NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", Object{"name": "projects/123", "projectId": "demo"}),
		NewAsset("//logging.googleapis.com/projects/123/locations/global/buckets/_Default", "logging.googleapis.com/LogBucket", Object{"name": "projects/123/locations/global/buckets/_Default"}),
	}}
}

func logViewClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Synthetic capabilities isolate metadata behavior; role membership is separate.
	c.viewerPolicy.permissions = map[string]bool{"logging.views.list": true, "logging.views.getIamPolicy": true}
	return c
}

func TestViewerLogViewsPaginationAliasesIAMProjection(t *testing.T) {
	lists, policies := 0, 0
	c := logViewClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "logging.googleapis.com" {
			t.Fatal(r.URL)
		}
		if r.Method == "GET" {
			lists++
			if r.URL.Path != "/v2/projects/123/locations/global/buckets/_Default/views" || r.URL.Query().Get("fields") != viewerLogViewFields {
				t.Fatal(r.URL)
			}
			if lists == 1 {
				return response(200, `{"views":[{"name":"projects/demo/locations/global/buckets/_Default/views/_AllLogs","filter":"LOG_ID(test)","unknown":"DO_NOT_KEEP"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"views":[{"name":"projects/123/locations/global/buckets/_Default/views/_AllLogs"},{"name":"projects/123/locations/global/buckets/_Default/views/selected"}]}`), nil
		}
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			t.Fatal(r.Method, r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"options":{"requestedPolicyVersion":3}}` {
			t.Fatal(string(body))
		}
		policies++
		if policies == 2 {
			return response(200, `{}`), nil
		}
		return response(200, `{"version":3,"_gcpbusterBindingsOnly":true,"unknown":"DO_NOT_KEEP","bindings":[{"role":"roles/logging.viewAccessor","members":["allAuthenticatedUsers"],"unknown":"DO_NOT_KEEP","condition":{"expression":"false","title":"conditional","unknown":"DO_NOT_KEEP"}}]}`), nil
	})
	s := logViewSnapshot()
	c.CollectViewerLogViews(context.Background(), &s, []string{"projects/demo", "projects/123"})
	if lists != 2 || policies != 2 || len(s.Assets) != 4 || hasCoverage(s, "failed") {
		t.Fatal(lists, policies, s)
	}
	if s.Assets[2].Name != "//logging.googleapis.com/projects/123/locations/global/buckets/_Default/views/_AllLogs" || s.Assets[3].IAM == nil || len(s.Assets[3].IAM) != 0 {
		t.Fatal(s)
	}
	if Str(Get(Obj(List(s.Assets[2].IAM["bindings"])[0]), "condition", "expression")) != "false" {
		t.Fatal(s.Assets[2])
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") || strings.Contains(string(b), "_gcpbusterBindingsOnly") {
		t.Fatal(string(b))
	}
}

func TestViewerLogViewsMalformedAndForeignRetainValid(t *testing.T) {
	c := logViewClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			return response(200, `{}`), nil
		}
		return response(200, `{"views":[null,{"name":"projects/999/locations/global/buckets/_Default/views/foreign"},{"name":"projects/123/locations/global/buckets/other/views/foreign"},{"name":"projects/123/locations/global/buckets/_Default/views/bad","filter":false},{"name":"projects/123/locations/global/buckets/_Default/views/good"}]}`), nil
	})
	s := logViewSnapshot()
	c.CollectViewerLogViews(context.Background(), &s, []string{"projects/123"})
	if len(s.Assets) != 3 || !hasCoverage(s, "failed") || !strings.HasSuffix(s.Assets[2].Name, "/good") {
		t.Fatal(s)
	}
}

func TestViewerLogViewsDenialsAndLateFailurePreserveMetadata(t *testing.T) {
	for _, mode := range []string{"list-permission", "iam-permission", "iam-server", "iam-malformed", "late-page"} {
		t.Run(mode, func(t *testing.T) {
			c := logViewClient(t, func(r *http.Request) (*http.Response, error) {
				if mode == "list-permission" {
					t.Fatal("unauthorized transport call")
				}
				if r.Method == "GET" {
					if r.URL.Query().Get("pageToken") != "" {
						return response(403, "DO_NOT_KEEP"), nil
					}
					next := ""
					if mode == "late-page" {
						next = `,"nextPageToken":"next"`
					}
					return response(200, `{"views":[{"name":"projects/123/locations/global/buckets/_Default/views/view"}]`+next+`}`), nil
				}
				if mode == "iam-permission" {
					t.Fatal("unauthorized policy call")
				}
				if mode == "iam-server" {
					return response(403, "DO_NOT_KEEP"), nil
				}
				if mode == "iam-malformed" {
					return response(200, `{"version":1,"bindings":[{"role":"roles/logging.viewAccessor","members":["allUsers"],"condition":{"expression":"true"}}]}`), nil
				}
				return response(200, `{}`), nil
			})
			if mode == "list-permission" {
				delete(c.viewerPolicy.permissions, "logging.views.list")
			}
			if mode == "iam-permission" {
				delete(c.viewerPolicy.permissions, "logging.views.getIamPolicy")
			}
			s := logViewSnapshot()
			c.CollectViewerLogViews(context.Background(), &s, []string{"projects/123"})
			want := 3
			if mode == "list-permission" {
				want = 2
			}
			if len(s.Assets) != want || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "DO_NOT_KEEP") {
				t.Fatal(string(b))
			}
		})
	}
}

func TestViewerLogViewsExplicitScopeAndParentKinds(t *testing.T) {
	for _, scope := range []string{"folders/123", "organizations/123"} {
		calls := 0
		c := logViewClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method == "POST" {
				return response(200, `{}`), nil
			}
			if r.URL.Path != "/v2/"+scope+"/locations/global/buckets/_Default/views" {
				t.Fatal(r.URL)
			}
			return response(200, `{"views":[{"name":"`+scope+`/locations/global/buckets/_Default/views/_Default"}]}`), nil
		})
		s := logViewSnapshot()
		name := scope + "/locations/global/buckets/_Default"
		s.Assets = append(s.Assets, NewAsset("//logging.googleapis.com/"+name, "logging.googleapis.com/LogBucket", Object{"name": name}))
		c.CollectViewerLogViews(context.Background(), &s, []string{scope})
		if calls != 2 || len(s.Assets) != 4 || hasCoverage(s, "failed") {
			t.Fatal(s, calls)
		}
	}
	c := logViewClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal("unexpected call", r.URL); return nil, nil })
	s := logViewSnapshot()
	s.Assets[1].Resource.Data["name"] = "projects/999/locations/global/buckets/_Default"
	c.CollectViewerLogViews(context.Background(), &s, []string{"projects/123"})
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerLogViewsTimestampsAndUnreachable(t *testing.T) {
	c := logViewClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			return response(200, `{}`), nil
		}
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"views":[{"name":"projects/123/locations/global/buckets/_Default/views/bad","createTime":"invalid"}],"unreachable":["us-west1"],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"views":[{"name":"projects/123/locations/global/buckets/_Default/views/good","createTime":"2026-01-01T00:00:00Z","updateTime":"2026-01-02T00:00:00.123Z"}]}`), nil
	})
	s := logViewSnapshot()
	c.CollectViewerLogViews(context.Background(), &s, []string{"projects/123"})
	if len(s.Assets) != 3 || !hasCoverage(s, "failed") || !strings.HasSuffix(s.Assets[2].Name, "/good") {
		t.Fatal(s)
	}
}
