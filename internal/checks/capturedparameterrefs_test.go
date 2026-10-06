package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestNativePureParameterREFIsReferenceNotCredential(t *testing.T) {
	for _, source := range []struct{ kind, resource string }{
		{"parameter_manager_raw", "//parametermanager.googleapis.com/projects/123/locations/global/parameters/PASSWORD/versions/v1"},
		{"parameter_template_raw", "//parametermanager.googleapis.com/projects/123/locations/global/templates/PASSWORD/versions/v1"},
	} {
		for _, tc := range []struct{ value, severity string }{
			{`__REF__("//secretmanager.googleapis.com/projects/456/secrets/password/versions/1")`, "info"},
			{`__REF__('//secretmanager.googleapis.com/projects/456/secrets/password/versions/latest')`, "info"},
			{`__REF__(//secretmanager.googleapis.com/projects/456/locations/us-central1/secrets/password/versions/prod)`, "info"},
			{`weak-password __REF__("//secretmanager.googleapis.com/projects/456/secrets/password/versions/1")`, "high"},
		} {
			for _, redact := range []bool{false, true} {
				rows := CapturedSampleAssets([]inventory.SecretSample{{SourceType: source.kind, Resource: source.resource, Path: "payload.data", Data: []byte(tc.value)}}, redact)
				if len(rows) != 1 {
					t.Fatal(source, tc, rows)
				}
				got := capturedConfigurationValue(rows[0], time.Time{})
				want := tc.value
				if redact {
					want = "[REDACTED]"
				}
				if len(got) != 1 || got[0].Severity != tc.severity || got[0].Evidence["value"] != want {
					t.Fatal(source, tc, got)
				}
			}
		}
	}
	for _, value := range []string{`__REF__("https://evil.invalid/secret")`, `__REF__("//secretmanager.googleapis.com/projects/456/secrets/password/versions/new")`, `prefix __REF__("//secretmanager.googleapis.com/projects/456/secrets/password/versions/1")`} {
		if parameterReferenceExpression(value) {
			t.Fatal("invalid or mixed reference excluded", value)
		}
	}
}
