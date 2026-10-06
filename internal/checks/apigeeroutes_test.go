package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestApigeeBasePathEvidenceTypedAndRedacted(t *testing.T) {
	d := inventory.Object{"status": "explicit_literal_path", "path_digest": strings.Repeat("a", 64), "segment_count": 2, "root_path": false, "path": "SENTINEL"}
	got := apigeeBasePathEvidence(d)
	raw, _ := json.Marshal(got)
	if got["status"] != "explicit_literal_path" || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(got)
	}
	d["root_path"] = true
	if apigeeBasePathEvidence(d)["status"] != "unknown" {
		t.Fatal("inconsistent root")
	}
	d["root_path"] = false
	d["path_digest"] = "bad"
	if apigeeBasePathEvidence(d)["status"] != "unknown" {
		t.Fatal("malformed digest")
	}
}
