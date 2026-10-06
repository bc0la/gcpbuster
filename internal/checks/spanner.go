package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func spannerDatabaseProtection(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "spanner.googleapis.com/Database" || !isFalse(val(a, "enableDropProtection")) {
		return nil
	}
	return result("low", "Spanner database deletion protection is explicitly disabled", "Enable database deletion protection where required, and independently review row-mutation permissions, backups and recovery objectives.", inventory.Object{"enable_drop_protection": false, "assessment": "Explicit database lifecycle setting only. Enabling this safeguard prevents database deletion and deletion of its containing instance until protection is disabled. It does not prevent row mutation or establish backup coverage, fine-grained privileges or effective deletion authority. Other databases may independently protect the containing instance. No SQL, sessions, backup restores or changes were performed."})
}

func spannerChangeStreamScope(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "spanner.googleapis.com/Database" {
		return nil
	}
	var out []Result
	seen := map[int]bool{}
	for _, raw := range arr(val(a, "_gcpbusterChangeStreams")) {
		d := obj(raw)
		index, ok := gatewaySecretInteger(d["statement_index"])
		if !ok || index < 0 || index >= 10000 || seen[index] || s(d["tracking_scope"]) != "all_tables" || s(d["dialect"]) != "GOOGLE_STANDARD_SQL" {
			continue
		}
		seen[index] = true
		out = append(out, Result{"info", "Spanner change stream is configured with FOR ALL", inventory.Object{"statement_index": index, "tracking_scope": "all_tables", "dialect": "GOOGLE_STANDARD_SQL", "assessment": "Configured all-table scope in returned GoogleSQL schema only. Capture options can exclude change types or values, and this does not establish effective read access, malicious intent, exfiltration or delivery to any consumer. No SQL execution, sessions or change-record reads occurred."}, "Review the all-table stream against approved change-data-capture requirements and independently review capture options and consumer permissions."})
	}
	return out
}
