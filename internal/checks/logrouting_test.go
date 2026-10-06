package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoggingBucketRetentionExplicitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, settings string
		want           int
	}{
		{"locked-minimum", `"retentionDays":1,"locked":true`, 1},
		{"unlocked-minimum", `"retentionDays":1,"locked":false`, 1},
		{"locked-long", `"retentionDays":365,"locked":true`, 1},
		{"unlocked-two", `"retentionDays":2,"locked":false`, 0},
		{"ordinary", `"retentionDays":30,"locked":false`, 0},
		{"maximum", `"retentionDays":3650,"locked":true`, 1},
		{"zero-not-zero-retention", `"retentionDays":0,"locked":true`, 0},
		{"negative", `"retentionDays":-1,"locked":true`, 0},
		{"fraction", `"retentionDays":1.5,"locked":true`, 0},
		{"out-of-range", `"retentionDays":3651,"locked":true`, 0},
		{"string-days", `"retentionDays":"1","locked":true`, 0},
		{"malformed-lock", `"retentionDays":1,"locked":"true"`, 0},
		{"missing-lock", `"retentionDays":1`, 0},
		{"missing-days", `"locked":true`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":"projects/demo/locations/global/buckets/_Default","lifecycleState":"ACTIVE",%s}`, tc.settings))
			got := loggingBucketRetention(a, time.Now())
			if len(got) != tc.want {
				t.Fatalf("want %d got %+v", tc.want, got)
			}
			for _, r := range got {
				if r.Severity != "info" || !strings.Contains(fmt.Sprint(r.Evidence["assessment"]), "not a universal compliance violation") {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestLoggingBucketRetentionUnknownAndRequiredSuppressed(t *testing.T) {
	for _, tc := range []struct{ name, resource, state string }{
		{"required", "projects/demo/locations/global/buckets/_Required", "ACTIVE"},
		{"deleted", "projects/demo/locations/global/buckets/logs", "DELETED"},
		{"pending-deletion", "projects/demo/locations/global/buckets/logs", "DELETE_REQUESTED"},
		{"missing-state", "projects/demo/locations/global/buckets/logs", ""},
		{"unknown-state", "projects/demo/locations/global/buckets/logs", "UNKNOWN"},
		{"missing-name", "", "ACTIVE"},
		{"malformed-name", "projects/demo/locations/global/buckets/../_Default", "ACTIVE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":%q,"lifecycleState":%q,"retentionDays":1,"locked":true}`, tc.resource, tc.state))
			if got := loggingBucketRetention(a, time.Now()); len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
}

func TestLoggingBucketLockedRetentionIsNotMaliciousness(t *testing.T) {
	a := asset("logging.googleapis.com/LogBucket", `{"name":"projects/demo/locations/us-central1/buckets/compliance","lifecycleState":"ACTIVE","retentionDays":365,"locked":true,"description":"DO_NOT_ECHO"}`)
	got := loggingBucketRetention(a, time.Now())
	if len(got) != 1 || got[0].Title != "Log bucket has a locked retention configuration" || strings.Contains(fmt.Sprint(got), "DO_NOT_ECHO") {
		t.Fatal(got)
	}
	if !strings.Contains(got[0].Remediation, "cannot be changed") {
		t.Fatal(got)
	}
}

func TestLoggingBucketRetentionDocumentedParentKinds(t *testing.T) {
	for _, parent := range []string{"projects/demo", "folders/123", "organizations/456", "billingAccounts/ABC123-DEF456-789ABC"} {
		for _, bucket := range []string{"_Default", "_Required"} {
			a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":%q,"lifecycleState":"ACTIVE","retentionDays":1,"locked":true}`, parent+"/locations/global/buckets/"+bucket))
			want := 1
			if bucket == "_Required" {
				want = 0
			}
			if got := loggingBucketRetention(a, time.Now()); len(got) != want {
				t.Fatalf("%s/%s: %+v", parent, bucket, got)
			}
		}
	}
	for _, parent := range []string{"folders/not-numeric", "organizations/not-numeric", "unknown/123", "folders/123/extra"} {
		a := asset("logging.googleapis.com/LogBucket", fmt.Sprintf(`{"name":%q,"lifecycleState":"ACTIVE","retentionDays":1,"locked":true}`, parent+"/locations/global/buckets/_Default"))
		if got := loggingBucketRetention(a, time.Now()); len(got) != 0 {
			t.Fatal(parent, got)
		}
	}
}
