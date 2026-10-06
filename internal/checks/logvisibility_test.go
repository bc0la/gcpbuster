package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogBucketVisibilityPendingDeletion(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		want        int
	}{
		{"logs", "DELETE_REQUESTED", 1}, {"_Required", "DELETE_REQUESTED", 0}, {"_Default", "DELETE_REQUESTED", 0}, {"logs", "ACTIVE", 0}, {"logs", "DELETED", 0}, {"logs", "", 0},
	} {
		a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":"projects/demo/locations/global/buckets/%s","lifecycleState":"%s","updateTime":"2000-01-01T00:00:00Z"}`, tc.name, tc.state))
		got := loggingBucketVisibility(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (got[0].Severity != "medium" || got[0].Evidence["deadline"] != nil || !strings.Contains(fmt.Sprint(got[0].Evidence["assessment"]), "continues routing")) {
			t.Fatal(got)
		}
	}
}

func TestLogBucketVisibilityFieldRestrictions(t *testing.T) {
	for _, tc := range []struct {
		fields, state string
		want          int
	}{
		{`["jsonPayload.secret","httpRequest","jsonPayload.secret"]`, "ACTIVE", 1}, {`[]`, "ACTIVE", 0}, {`null`, "ACTIVE", 0}, {`{}`, "ACTIVE", 0}, {`[42]`, "ACTIVE", 0}, {`["unknown.field"]`, "ACTIVE", 0}, {`["jsonPayload."]`, "ACTIVE", 0}, {`["jsonPayload.secret"]`, "CREATING", 0}, {`["jsonPayload.secret"]`, "UNKNOWN", 0},
	} {
		a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":"projects/demo/locations/global/buckets/logs","lifecycleState":"%s","restrictedFields":%s,"analyticsEnabled":true}`, tc.state, tc.fields))
		got := loggingBucketVisibility(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (got[0].Severity != "info" || !strings.Contains(fmt.Sprint(got[0].Evidence["assessment"]), "no linked dataset")) {
			t.Fatal(got)
		}
	}
}
