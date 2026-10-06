package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerLogFilterCannotBeOverridden(t *testing.T) {
	for _, id := range []string{"cloudaudit.googleapis.com/data_access", "cloudaudit.googleapis.com/access_transparency", "externalaudit.googleapis.com/data_access", "externalaudit.googleapis.com/access_transparency"} {
		if !strings.Contains(viewerLogExclusion, `NOT LOG_ID("`+id+`")`) {
			t.Fatal("missing conservative audit exclusion", id)
		}
		private, err := viewerLogEntry("projects/test/logs/" + strings.ReplaceAll(id, "/", "%2F"))
		if err != nil || !private {
			t.Fatal("audit payload allowed", id, err)
		}
	}
	for _, filter := range []string{`severity>=ERROR`, `(severity>=ERROR OR severity=INFO)`, `textPayload="a # -- ( )"`, `textPayload="escaped \" quote"`} {
		got, err := viewerLogFilter(filter)
		if err != nil || !strings.HasSuffix(got, ") AND "+viewerLogExclusion) {
			t.Fatalf("%q: %s %v", filter, got, err)
		}
	}
	for _, filter := range []string{`) OR logName:* #`, `severity>=ERROR --`, `(`, `"unfinished`, `)`} {
		if _, err := viewerLogFilter(filter); err == nil {
			t.Fatalf("accepted %q", filter)
		}
	}
}

func TestViewerLogsSkipPrivatePayloadsEvenIfUpstreamIgnoresFilter(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		var body Object
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(Str(body["filter"]), viewerLogExclusion) {
			t.Fatal("missing mandatory private-log exclusion")
		}
		return response(200, `{"entries":[
		{"logName":"projects/test/logs/cloudaudit.googleapis.com%2Fdata_access","insertId":"PRIVATE_ID","textPayload":"password=PRIVATE_SECRET"},
		{"logName":"organizations/123/logs/cloudaudit.googleapis.com%2faccess_transparency","insertId":"TRANSPARENCY_ID","jsonPayload":{"password":"PRIVATE_SECRET"}},
		{"logName":"projects/test/logs/externalaudit.googleapis.com%2Fdata_access","insertId":"EXTERNAL_PRIVATE_ID","textPayload":"password=PRIVATE_SECRET"},
		{"logName":"projects/test/logs/externalaudit.googleapis.com%2faccess_transparency","insertId":"EXTERNAL_TRANSPARENCY_ID","textPayload":"password=PRIVATE_SECRET"},
		{"logName":"projects/test/logs/app","insertId":"ordinary","textPayload":"password=ORDINARY_SECRET"}
		]}`), nil
	})
	s := Snapshot{}
	c.CollectLogs(context.Background(), &s, []string{"projects/test"}, logOptions())
	if len(s.Assets) != 1 {
		t.Fatal(s)
	}
	d := s.Assets[0].Resource.Data
	if len(List(d["matches"])) != 1 || d["entriesInspected"] != 1 || d["privateEntriesExcluded"] != 4 {
		t.Fatal(d)
	}
	b, _ := json.Marshal(s)
	for _, forbidden := range []string{"PRIVATE_ID", "TRANSPARENCY_ID", "EXTERNAL_PRIVATE_ID", "EXTERNAL_TRANSPARENCY_ID", "PRIVATE_SECRET", "ORDINARY_SECRET"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("persisted %s", forbidden)
		}
	}
}

func TestViewerLogsUnclassifiableNamesNeverInspected(t *testing.T) {
	for _, name := range []string{"", "unknown", "projects/test/logs/", "projects/test/logs/cloudaudit.googleapis.com%252Fdata_access", "projects/test/logs/%zz"} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(Object{"entries": []any{Object{"logName": name, "textPayload": "password=PRIVATE_UNCLASSIFIABLE"}}})
			c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, string(b)), nil })
			s := Snapshot{}
			c.CollectLogs(context.Background(), &s, []string{"projects/test"}, logOptions())
			if len(List(s.Assets[0].Resource.Data["matches"])) != 0 || Bool(s.Assets[0].Resource.Data["complete"]) || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}
