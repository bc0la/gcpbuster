package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogBigQueryLinkConfiguredNotExposure(t *testing.T) {
	for _, tc := range []struct {
		state, dataset string
		want           int
	}{
		{"ACTIVE", "bigquery.googleapis.com/projects/demo/datasets/linked", 1},
		{"CREATING", "bigquery.googleapis.com/projects/demo/datasets/linked", 0},
		{"DELETE_REQUESTED", "bigquery.googleapis.com/projects/demo/datasets/linked", 0},
		{"", "bigquery.googleapis.com/projects/demo/datasets/linked", 0},
		{"ACTIVE", "", 0}, {"ACTIVE", "demo:linked", 0},
		{"ACTIVE", "bigquery.googleapis.com/projects/demo/datasets/other", 0},
	} {
		a := asset("logging.googleapis.com/Link", fmt.Sprintf(`{"name":"projects/demo/locations/global/buckets/logs/links/linked","lifecycleState":%q,"bigqueryDataset":{"datasetId":%q},"description":"DO_NOT_ECHO"}`, tc.state, tc.dataset))
		got := loggingBigQueryLink(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (got[0].Severity != "info" || !strings.Contains(fmt.Sprint(got[0].Evidence["assessment"]), "does not establish public exposure") || strings.Contains(fmt.Sprint(got), "DO_NOT_ECHO")) {
			t.Fatal(got)
		}
	}
}
