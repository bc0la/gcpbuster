package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"time"
)

const SecretScanFindingType = "gcpbuster.googleapis.com/SecretScanFinding"

func kingfisherSecrets(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	if a.Type != SecretScanFindingType || d["scanner"] != "kingfisher" || d["credential_validation_performed"] != false {
		return nil
	}
	if s(d["rule_id"]) == "" || len(s(d["match"])) > 4<<20 {
		return nil
	}
	severity := "high"
	if strings.EqualFold(s(d["validation"]), "valid") {
		severity = "critical"
	} else if strings.EqualFold(s(d["confidence"]), "low") {
		severity = "medium"
	}
	evidence := inventory.Object{"scanner": "kingfisher", "credential_validation_performed": false, "assessment": "Kingfisher detection on explicitly collected configuration; --no-validate was enforced. Reported validation status is scanner evidence, not a credential test performed by GCPBuster. Actual matches are retained for manual validation unless --redact-secrets was selected."}
	for _, field := range []string{"rule_id", "rule_name", "match", "source", "source_type", "source_field", "source_location", "source_revision", "pull_command", "refetch_metadata", "refetch_instruction", "check", "line", "confidence", "validation", "redacted"} {
		evidence[field] = d[field]
	}
	return result(severity, "Kingfisher detected a credential candidate", "Inspect the matched value in the protected report, establish its ownership and exposure, and rotate/revoke confirmed secrets. Do not treat a pattern match as proof of validity.", evidence)
}
