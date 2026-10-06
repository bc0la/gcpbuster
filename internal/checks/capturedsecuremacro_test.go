package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestSecureMacroReferenceInformationalNoDereference(t *testing.T) {
	for _, value := range []string{"${secure(password)}", "${secure(database.password-key)}"} {
		if candidate(value) {
			t.Fatal("secure reference candidate", value)
		}
		for _, source := range []string{"datafusion_connection_config", "datafusion_pipeline_config"} {
			path := "plugin.properties.password"
			if source == "datafusion_pipeline_config" {
				path = "configuration.stages[0].plugin.properties.password"
			}
			sample := inventory.SecretSample{SourceType: source, Resource: "//datafusion.googleapis.com/projects/123/locations/us-central1/instances/etl/namespaces/ns/connections/id", Path: path, Data: []byte("password=" + value)}
			for _, redact := range []bool{false, true} {
				assets := CapturedSampleAssets([]inventory.SecretSample{sample}, redact)
				if len(assets) != 1 {
					t.Fatal(assets)
				}
				r := capturedConfigurationValue(assets[0], time.Time{})
				if len(r) != 1 || r[0].Severity != "info" {
					t.Fatal(r)
				}
				want := value
				if redact {
					want = "[REDACTED]"
				}
				if r[0].Evidence["value"] != want {
					t.Fatal("reference changed", r)
				}
			}
		}
	}
	if !candidate("ordinary_actual_password") || !candidate("${secure(password)}suffix") {
		t.Fatal("ordinary values wrongly excluded")
	}
}
