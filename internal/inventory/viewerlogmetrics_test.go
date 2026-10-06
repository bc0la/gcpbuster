package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func logMetricClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"logging.logMetrics.list": true}
	return c
}

func TestViewerLogMetricsPaginationAliasesProjection(t *testing.T) {
	calls := 0
	c := logMetricClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "logging.googleapis.com" || r.URL.Path != "/v2/projects/123/metrics" || r.URL.Query().Get("fields") != viewerLogMetricFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"metrics":[{"name":"nginx/requests","resourceName":"projects/demo/metrics/nginx%2Frequests","disabled":true,"filter":"DO_NOT_KEEP","labelExtractors":{"x":"DO_NOT_KEEP"}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"metrics":[{"name":"nginx/requests"},{"name":"special%+!*'(),.-_","disabled":false,"createTime":"2026-01-01T00:00:00Z"}]}`), nil
	})
	s := logViewSnapshot()
	s.Assets = s.Assets[:1]
	c.CollectViewerLogMetrics(context.Background(), &s, []string{"projects/demo", "projects/123", "organizations/456"})
	if calls != 2 || len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
	if s.Assets[1].Name != "//logging.googleapis.com/projects/123/metrics/nginx%2Frequests" {
		t.Fatal(s.Assets[1])
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}

func TestViewerLogMetricsMalformedRetainsValid(t *testing.T) {
	c := logMetricClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"metrics":[null,{"name":"/leading"},{"name":"bad?"},{"name":"foreign","resourceName":"projects/999/metrics/foreign"},{"name":"wrong","resourceName":"projects/123/metrics/other"},{"name":"badbool","disabled":"true"},{"name":"badtime","updateTime":"bad"},{"name":"good","disabled":true}]}`), nil
	})
	s := logViewSnapshot()
	s.Assets = s.Assets[:1]
	c.CollectViewerLogMetrics(context.Background(), &s, []string{"projects/123"})
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") || Str(s.Assets[1].Resource.Data["name"]) != "good" {
		t.Fatal(s)
	}
}

func TestViewerLogMetricsDeniedAndLateFailure(t *testing.T) {
	for _, mode := range []string{"permission", "server", "late"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := logMetricClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "permission" {
					t.Fatal("transport called without baseline permission")
				}
				if mode == "late" && calls == 1 {
					return response(200, `{"metrics":[{"name":"kept","disabled":true}],"nextPageToken":"next"}`), nil
				}
				return response(403, `{}`), nil
			})
			if mode == "permission" {
				c.viewerPolicy.permissions = map[string]bool{}
			}
			s := logViewSnapshot()
			s.Assets = s.Assets[:1]
			c.CollectViewerLogMetrics(context.Background(), &s, []string{"projects/123"})
			want := 1
			if mode == "late" {
				want = 2
			}
			if !hasCoverage(s, "failed") || len(s.Assets) != want {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerLogMetricsInvalidScopesNoTransport(t *testing.T) {
	c := logMetricClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerLogMetrics(context.Background(), &s, []string{"projects/x/metrics/y", "https://example.com", "folders/123"})
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
