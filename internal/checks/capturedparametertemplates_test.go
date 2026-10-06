package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestParameterTemplateFullNativeInformationAndNameContext(t *testing.T) {
	for _, name := range []string{"blueprint", "password_blueprint"} {
		raw := "region: {{.region}}\nordinary: true\n"
		sample := inventory.SecretSample{SourceType: "parameter_template_raw", Resource: "//parametermanager.googleapis.com/projects/123/locations/global/templates/" + name + "/versions/v", Path: "payload.data", Data: []byte(raw)}
		for _, redact := range []bool{false, true} {
			assets := CapturedSampleAssets([]inventory.SecretSample{sample}, redact)
			if len(assets) != 1 {
				t.Fatal(assets)
			}
			r := capturedConfigurationValue(assets[0], time.Time{})
			wantSeverity := "info"
			if name == "password_blueprint" {
				wantSeverity = "high"
			}
			if len(r) != 1 || r[0].Severity != wantSeverity {
				t.Fatal(r)
			}
			want := raw
			if redact {
				want = "[REDACTED]"
			}
			if r[0].Evidence["value"] != want {
				t.Fatal("template changed/truncated", r)
			}
		}
	}
}
