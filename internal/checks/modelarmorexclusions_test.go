package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func modelArmorExclusionAsset() inventory.Asset {
	a := asset("gcpbuster.googleapis.com/ModelArmorTemplate", `{"filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED"},"raiSettings":{"raiFilters":[{"filterType":"HATE_SPEECH"}]}},"_gcpbusterModelArmorExclusions":{"complete":true,"rules":[{"rule_set_index":0,"rule_index":1,"filter_types":["PROMPT_INJECTION_AND_JAILBREAK","RESPONSIBLE_AI"],"matching_scope":"MATCHING_SCOPE_PARTIAL_MATCH","catch_all":true}]}}`)
	a.Name = "//modelarmor.googleapis.com/projects/123/locations/us-central1/templates/template"
	return a
}

func TestModelArmorCatchAllEnabledFiltersOnly(t *testing.T) {
	a := modelArmorExclusionAsset()
	got := modelArmorExclusionConfiguration(a, time.Now())
	if len(got) != 1 {
		t.Fatal(got)
	}
	marker := obj(a.Resource.Data["_gcpbusterModelArmorExclusions"])
	marker["complete"] = false
	if len(modelArmorExclusionConfiguration(a, time.Now())) != 0 {
		t.Fatal("incomplete")
	}
	marker["complete"] = true
	a.Resource.Data["filterConfig"] = inventory.Object{"piAndJailbreakFilterSettings": inventory.Object{"filterEnforcement": "DISABLED"}}
	if len(modelArmorExclusionConfiguration(a, time.Now())) != 0 {
		t.Fatal("disabled or missing filters")
	}
	a = modelArmorExclusionAsset()
	a.Type = "gcpbuster.googleapis.com/ModelArmorFloorSetting"
	if len(modelArmorExclusionConfiguration(a, time.Now())) != 0 {
		t.Fatal("floor unsupported")
	}
}

func TestModelArmorCatchAllMalformedAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{{"catch_all", "true"}, {"catch_all", false}, {"rule_index", -1}, {"rule_index", 1.5}, {"rule_set_index", 4096}, {"matching_scope", "MATCHING_SCOPE_FULL_MATCH"}, {"filter_types", []any{"MALICIOUS_URI"}}, {"filter_types", []any{"RESPONSIBLE_AI", "RESPONSIBLE_AI"}}} {
		a := modelArmorExclusionAsset()
		row := obj(arr(obj(a.Resource.Data["_gcpbusterModelArmorExclusions"])["rules"])[0])
		row[tc.key] = tc.value
		if len(modelArmorExclusionConfiguration(a, time.Now())) != 0 {
			t.Fatal(tc)
		}
	}
	a := modelArmorExclusionAsset()
	row := obj(arr(obj(a.Resource.Data["_gcpbusterModelArmorExclusions"])["rules"])[0])
	row["pattern"] = "SENTINEL"
	row["dictionary"] = "SENTINEL"
	got := modelArmorExclusionConfiguration(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
}
