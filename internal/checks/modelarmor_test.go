package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestModelArmorExplicitConfigurationOnly(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"DISABLED"}}}`, 1},
		{`{"filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED","confidenceLevel":"HIGH"}}}`, 1},
		{`{"filterConfig":{"piAndJailbreakFilterSettings":{"confidenceLevel":"HIGH"}}}`, 0},
		{`{"filterConfig":{"sdpSettings":{"basicConfig":{"filterEnforcement":"DISABLED"}}}}`, 1},
		{`{"filterConfig":{"sdpSettings":{"basicConfig":{"filterEnforcement":"DISABLED"},"advancedConfig":{}}}}`, 0},
		{`{"filterConfig":{"maliciousUriFilterSettings":{"filterEnforcement":"DISABLED"}}}`, 1},
		{`{"templateMetadata":{"enforcementType":"INSPECT_ONLY"}}`, 1},
		{`{"templateMetadata":{"ignorePartialInvocationFailures":true}}`, 1},
		{`{"templateMetadata":{"ignorePartialInvocationFailures":"true"}}`, 0},
		{`{}`, 0}, {`{"filterConfig":{"sdpSettings":{"basicConfig":{"filterEnforcement":"SDP_BASIC_CONFIG_ENFORCEMENT_UNSPECIFIED"}}}}`, 0},
		{`{"projection_complete":false,"templateMetadata":{"enforcementType":"INSPECT_ONLY"}}`, 0},
		{`{"filterConfig":{"raiSettings":{"raiFilters":[{"filterType":"HATE_SPEECH","confidenceLevel":"HIGH"},{"filterType":"HATE_SPEECH","confidenceLevel":"LOW_AND_ABOVE"}]}}}`, 0},
	} {
		a := asset("gcpbuster.googleapis.com/ModelArmorTemplate", tc.body)
		a.Name = "//modelarmor.googleapis.com/projects/123/locations/us-central1/templates/template"
		got := modelArmorFilterConfiguration(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestModelArmorRAIThresholdsAndSafeEvidence(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/ModelArmorTemplate", `{"filterConfig":{"raiSettings":{"raiFilters":[{"filterType":"HATE_SPEECH","confidenceLevel":"HIGH"},{"filterType":"DANGEROUS","confidenceLevel":"LOW_AND_ABOVE"},{"filterType":"SENTINEL","confidenceLevel":"HIGH"}]}},"templateMetadata":{"customPromptSafetyErrorMessage":"SENTINEL"}}`)
	a.Name = "//modelarmor.googleapis.com/projects/123/locations/us-central1/templates/template"
	got := modelArmorFilterConfiguration(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	a.Type = "gcpbuster.googleapis.com/ModelArmorFloorSetting"
	if len(modelArmorFilterConfiguration(a, time.Now())) != 0 {
		t.Fatal("floor not template")
	}
}
