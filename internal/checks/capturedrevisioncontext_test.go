package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestRetainedRunRevisionContextActualAndRedacted(t *testing.T) {
	for _, tc := range []struct{ path, value string }{
		{"serviceAccount", "serviceAccount=revision@example.invalid"},
		{"containers[0].image", "image=example.invalid/image:revision"},
	} {
		for _, redact := range []bool{false, true} {
			assets := CapturedSampleAssets([]inventory.SecretSample{{SourceType: "run_revision_config", Resource: "//run.googleapis.com/projects/demo/locations/us-central1/services/s/revisions/s-00001-abc", Path: tc.path, Data: []byte(tc.value)}}, redact)
			if len(assets) != 1 {
				t.Fatal("revision context omitted", tc, assets)
			}
			results := capturedConfigurationValue(assets[0], time.Time{})
			if len(results) != 1 || results[0].Severity != "info" {
				t.Fatal("revision context not informational", results)
			}
			want := tc.value
			if tc.path == "serviceAccount" {
				want = "revision@example.invalid"
			} else {
				want = "example.invalid/image:revision"
			}
			if redact {
				want = "[REDACTED]"
			}
			if results[0].Evidence["value"] != want {
				t.Fatal("revision context changed", results)
			}
		}
	}
	for _, tc := range []struct{ path, data string }{
		{"serviceAccount", "image=example.invalid"},
		{"containers[0].image", "serviceAccount=revision@example.invalid"},
		{"template.containers[0].image", "image=example.invalid"},
	} {
		if rows := CapturedSampleAssets([]inventory.SecretSample{{SourceType: "run_revision_config", Resource: "//run.googleapis.com/projects/demo/locations/us-central1/services/s/revisions/s-00001-abc", Path: tc.path, Data: []byte(tc.data)}}, false); len(rows) != 0 {
			t.Fatal("unreviewed revision context accepted", tc, rows)
		}
	}
}
