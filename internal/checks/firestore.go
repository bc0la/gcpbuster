package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func firestoreDatabaseProtection(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "firestore.googleapis.com/Database" || s(val(a, "deleteProtectionState")) != "DELETE_PROTECTION_DISABLED" {
		return nil
	}
	return result("low", "Firestore database deletion protection is explicitly disabled", "Enable deletion protection where required, and independently review deletion permissions and recovery plans.", inventory.Object{"delete_protection_state": "DELETE_PROTECTION_DISABLED", "assessment": "Explicit database lifecycle configuration only. Deletion protection blocks deleting the database until disabled; it does not prevent document or entity deletion and does not establish effective deletion authority, backup coverage or recoverability. No database or data operations were performed."})
}

func firestorePITR(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "firestore.googleapis.com/Database" || s(val(a, "pointInTimeRecoveryEnablement")) != "POINT_IN_TIME_RECOVERY_DISABLED" {
		return nil
	}
	return result("info", "Firestore extended point-in-time recovery is explicitly disabled", "Review whether the database recovery objectives require enabling PITR, together with independent backup and retention requirements.", inventory.Object{"point_in_time_recovery": "POINT_IN_TIME_RECOVERY_DISABLED", "assessment": "Configured recovery policy only. Disabled PITR retains the documented one-hour version-history window rather than the extended seven-day PITR window; it does not imply no recovery or no backups. Actual recoverable timestamps and incident recovery were not verified. No historical document reads, exports, clones or restores occurred."})
}
