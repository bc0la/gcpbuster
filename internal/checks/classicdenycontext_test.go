package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestClassicDenyEvidenceScopedRedactedAndNotEffective(t *testing.T) {
	raw := inventory.Object{"status": "definitely_shadowed_by_observed_classic_deny", "snapshot_coverage": "completed", "effective_admission": "unknown", "denies": []any{inventory.Object{"firewall_resource": "//compute.googleapis.com/projects/demo/global/firewalls/deny", "priority": 1000, "secret": "SENTINEL"}}, "assessment": "SENTINEL"}
	got := classicDenyContextEvidence(raw, "demo", 1000)
	if got["status"] != raw["status"] || got["effective_admission"] != "unknown" {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENTINEL") {
		t.Fatal("raw retained")
	}
	for _, mode := range []string{"foreign", "lower_priority", "missing_coverage", "unsafe_status"} {
		copy := inventory.Object{}
		for k, v := range raw {
			copy[k] = v
		}
		switch mode {
		case "foreign":
			if classicDenyContextEvidence(copy, "other", 1000)["status"] != "unknown" {
				t.Fatal(mode)
			}
			continue
		case "lower_priority":
			if classicDenyContextEvidence(copy, "demo", 999)["status"] != "unknown" {
				t.Fatal(mode)
			}
			continue
		case "missing_coverage":
			copy["snapshot_coverage"] = "unknown"
		case "unsafe_status":
			copy["effective_admission"] = "blocked"
		}
		if classicDenyContextEvidence(copy, "demo", 1000)["status"] != "unknown" {
			t.Fatal(mode)
		}
	}
}
