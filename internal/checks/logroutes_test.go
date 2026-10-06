package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLogRouteDetectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{}`, 0},
		{`{"destination":"storage.googleapis.com/bucket","disabled":true}`, 0},
		{`{"destination":"storage.googleapis.com/bucket"}`, 1},
		{`{"destination":"pubsub.googleapis.com/projects/p/topics/t"}`, 1},
		{`{"destination":"bigquery.googleapis.com/projects/p/datasets/d"}`, 1},
		{`{"destination":"logging.googleapis.com/projects/p/locations/global/buckets/_Default"}`, 0},
		{`{"destination":"logging.googleapis.com/projects/p","includeChildren":true}`, 1},
		{`{"destination":"logging.googleapis.com/projects/p","includeChildren":true,"interceptChildren":true,"filter":"PRIVATE_FILTER_LITERAL"}`, 1},
	} {
		got := loggingRoutes(asset("logging.googleapis.com/LogSink", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_FILTER_LITERAL") {
			t.Fatal("raw filter copied into evidence")
		}
	}
}
