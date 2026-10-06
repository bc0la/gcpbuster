package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func bigtableTableProtection(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "bigtableadmin.googleapis.com/Table" || !isFalse(val(a, "deletionProtection")) {
		return nil
	}
	return result("low", "Bigtable table deletion protection is explicitly disabled", "Enable deletion protection for tables requiring this safeguard, and separately review row-mutation grants and recovery plans.", inventory.Object{"deletion_protection": false, "assessment": "Explicit table lifecycle setting only. Deletion protection guards table, column-family and containing-instance deletion; it is not a row-mutation control or a backup. Other view protection and IAM controls can still restrict deletion. No data reads, table changes or recovery operations occurred."})
}

func bigtableAuthorizedViewScope(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.BigtableAuthorizedViewType {
		return nil
	}
	d := obj(val(a, "subset_scope"))
	complete, cok := d["complete"].(bool)
	allRows, aok := d["all_rows"].(bool)
	rows, rok := gatewaySecretInteger(d["row_prefix_count"])
	families, fok := gatewaySecretInteger(d["family_count"])
	broad, bok := gatewaySecretInteger(d["all_qualifiers_family_count"])
	if !cok || !complete || !aok || !allRows || !rok || rows < 1 || rows > 10000 || !fok || families < 1 || families > 10000 || !bok || broad < 1 || broad > families {
		return nil
	}
	return result("info", "Bigtable authorized view includes all rows and all qualifiers in selected families", "Review whether this view should use narrower row or qualifier prefixes, and separately review IAM access to the view and underlying table.", inventory.Object{"all_rows": true, "selected_family_count": families, "all_qualifiers_family_count": broad, "assessment": "Validated configured subset only: an explicit empty row prefix includes all rows, and explicit empty qualifier prefixes include all qualifiers in the indicated number of selected families. This does not include every table family or establish any IAM access, public access, data readability or reachability. No row reads or changes occurred."})
}
