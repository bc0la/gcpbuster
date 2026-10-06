package inventory

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestLoggingConfigPaginationAncestorIdentityAndReservedSinks(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "logging.googleapis.com" {
			t.Fatal(r.URL)
		}
		if strings.HasSuffix(r.URL.Path, "exclusions") {
			return response(200, `{"exclusions":[{"name":"drop_debug","filter":"severity=DEBUG"}]}`), nil
		}
		if r.URL.Query().Get("filter") != `in_scope("ALL")` {
			t.Fatal("ancestor filter missing")
		}
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"sinks":[{"name":"_Default","destination":"logging.googleapis.com/projects/p/locations/global/buckets/_Default"}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"sinks":[{"name":"central","resourceName":"organizations/1/sinks/central","destination":"logging.googleapis.com/projects/logs","includeChildren":true,"interceptChildren":true}]}`), nil
	})
	s := Snapshot{}
	c.CollectLoggingConfig(context.Background(), &s, []string{"projects/p", "projects/p"})
	if calls != 3 || len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
	if s.Assets[1].Name != "//logging.googleapis.com/organizations/1/sinks/central" {
		t.Fatal("ancestor mislabeled", s.Assets[1])
	}
}

func TestLoggingConfigFailuresPreserveKnownRecords(t *testing.T) {
	for _, bad := range []string{`{"sinks":{}}`, `{"sinks":[{"name":"central","includeChildren":true}]}`, `{"nextPageToken":42}`, `DENIED`} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "exclusions") {
				return response(200, `{}`), nil
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"sinks":[{"name":"known","destination":"storage.googleapis.com/bucket"}],"nextPageToken":"next"}`), nil
			}
			if bad == "DENIED" {
				return response(403, "private upstream message"), nil
			}
			return response(200, bad), nil
		})
		s := Snapshot{}
		c.CollectLoggingConfig(context.Background(), &s, []string{"projects/p"})
		if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
			t.Fatal(bad, s)
		}
	}
}
