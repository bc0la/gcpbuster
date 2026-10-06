package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestParameterRawValuesAndSensitiveNameContext(t *testing.T) {
	for _, tc := range []struct{ name, value, severity string }{
		{"PASSWORD", "weak-password", "high"},
		{"APP_CONFIG", "ordinary: configuration\n", "info"},
		{"PASSWORD", "projects/demo/secrets/password/versions/latest", "info"},
	} {
		for _, redact := range []bool{false, true} {
			sample := inventory.SecretSample{SourceType: "parameter_manager_raw", Resource: "//parametermanager.googleapis.com/projects/123/locations/global/parameters/" + tc.name + "/versions/v1", Path: "payload.data", Data: []byte(tc.value)}
			assets := CapturedSampleAssets([]inventory.SecretSample{sample}, redact)
			if len(assets) != 1 {
				t.Fatal(tc, assets)
			}
			got := capturedConfigurationValue(assets[0], time.Time{})
			if len(got) != 1 || got[0].Severity != tc.severity {
				t.Fatal(tc, got)
			}
			want := tc.value
			if redact {
				want = "[REDACTED]"
			}
			if got[0].Evidence["value"] != want {
				t.Fatal("raw parameter value changed", tc)
			}
		}
	}
}
