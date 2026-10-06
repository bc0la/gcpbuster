package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestNestedDataflowSensitiveParentContext(t *testing.T) {
	a := inventory.NewAsset("//dataflow.googleapis.com/projects/123/locations/us-central1/jobs/job", "dataflow.googleapis.com/Job", inventory.Object{"environment": inventory.Object{"sdkPipelineOptions": inventory.Object{"PASSWORD": inventory.Object{"value": "arbitrary_full_password"}}}})
	c := inventory.NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]inventory.Asset{a})
	ss := c.Samples()
	if len(ss) != 1 || string(ss[0].Data) != "PASSWORD.value=arbitrary_full_password" {
		t.Fatal(ss)
	}
	for _, redact := range []bool{false, true} {
		assets := CapturedSampleAssets(ss, redact)
		if len(assets) != 1 {
			t.Fatal(assets)
		}
		r := capturedConfigurationValue(assets[0], time.Time{})
		if len(r) != 1 || r[0].Severity != "high" {
			t.Fatal(r)
		}
		want := "arbitrary_full_password"
		if redact {
			want = "[REDACTED]"
		}
		if r[0].Evidence["value"] != want {
			t.Fatal(r)
		}
	}
}
