package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSourceGenerationAndNoListing(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") == "" || !strings.HasSuffix(r.URL.EscapedPath(), "/o/source%2Fconfig.env") {
			t.Fatal("unexpected source request", r.URL)
		}
		if r.URL.Query().Get("alt") == "media" {
			if r.URL.Query().Get("generation") != "42" {
				t.Fatal("unpinned content")
			}
			return response(200, "password=SOURCE_VALUE_NOT_SAVED"), nil
		}
		return response(200, `{"name":"source/config.env","generation":"42","size":"31"}`), nil
	})
	s := Snapshot{Assets: []Asset{NewAsset("functions/example", "cloudfunctions.googleapis.com/CloudFunction", Object{"sourceArchiveUrl": "gs://test-bucket/source/config.env"})}}
	c.CollectSources(context.Background(), &s, storageOptions())
	if calls != 2 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || len(s.Assets) != 2 {
		t.Fatal(calls, s)
	}
	if Str(s.Assets[1].Resource.Data["originResource"]) != "functions/example" {
		t.Fatal("missing provenance")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_VALUE_NOT_SAVED") {
		t.Fatal("source leaked")
	}
}

func logOptions() LogOptions {
	return LogOptions{MaxEntries: 10, MaxPages: 3, Since: time.Unix(100, 0), Until: time.Unix(200, 0), Filter: "severity>=ERROR"}
}

func TestLogsEmptyPagePaginationAndRedaction(t *testing.T) {
	calls := 0
	firstFilter := ""
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://logging.googleapis.com/v2/entries:list" || r.Header.Get("Authorization") == "" {
			t.Fatal("unexpected log request")
		}
		var body Object
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if names := List(body["resourceNames"]); len(names) != 1 || names[0] != "projects/test" {
			t.Fatal(body)
		}
		if calls == 1 {
			firstFilter = Str(body["filter"])
			return response(200, `{"nextPageToken":"second"}`), nil
		}
		if Str(body["pageToken"]) != "second" || Str(body["filter"]) != firstFilter {
			t.Fatal("pagination query changed")
		}
		return response(200, `{"entries":[{"textPayload":"password=LOG_VALUE_NOT_SAVED","logName":"projects/test/logs/app","timestamp":"2026-10-05T00:00:00Z"}]}`), nil
	})
	s := Snapshot{}
	c.CollectLogs(context.Background(), &s, []string{"projects/test", "projects/test"}, logOptions())
	if calls != 2 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || len(s.Assets) != 1 || !Bool(s.Assets[0].Resource.Data["complete"]) {
		t.Fatal(calls, s)
	}
	if len(List(s.Assets[0].Resource.Data["matches"])) != 1 {
		t.Fatal("missing credential candidate")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "LOG_VALUE_NOT_SAVED") {
		t.Fatal("log payload persisted")
	}
}

func TestLogsPartialAndMalformed(t *testing.T) {
	for _, body := range []string{`{"entries":{}}`, `{"entries":[null]}`, `{"nextPageToken":42}`, `{"nextPageToken":"more"}`} {
		t.Run(body, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
			s := Snapshot{}
			opts := logOptions()
			opts.MaxPages = 1
			c.CollectLogs(context.Background(), &s, []string{"projects/test"}, opts)
			if !hasCoverage(s, "failed") && !hasCoverage(s, "incomplete") {
				t.Fatal("partial query marked clean")
			}
			if Bool(s.Assets[0].Resource.Data["complete"]) {
				t.Fatal("invalid completion")
			}
		})
	}
}
