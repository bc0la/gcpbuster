package checks

import (
	"testing"
	"time"
)

func TestLoggingMetricDisabledIsExplicitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"disabled":true}`, 1}, {`{"disabled":false}`, 0}, {`{}`, 0}, {`{"disabled":"true"}`, 0}, {`{"disabled":null}`, 0}, {`{"disabled":1}`, 0},
	} {
		got := loggingMetrics(asset("logging.googleapis.com/LogMetric", tc.body), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (got[0].Evidence["disabled"] != true || got[0].Evidence["assessment"] == nil) {
			t.Fatal(got)
		}
	}
}
