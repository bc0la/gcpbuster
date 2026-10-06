package checks

import (
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

// Cloud SQL audit configuration uses cloudsql.googleapis.com, not the
// sqladmin.googleapis.com inventory/API hostname. users.update is DATA_WRITE.
func cloudSQLUserUpdateAudit(a inventory.Asset, _ time.Time) []Result {
	rows := serviceReadAudit(a, "cloudsql.googleapis.com", "Cloud SQL user-password update", []string{"DATA_WRITE"}, map[string]string{"DATA_WRITE": "user updates, including delegated managed-secret rotation password changes"})
	for i := range rows {
		e := rows[i].Evidence
		e["resource"] = a.Resource.Data["resource"]
		e["method"] = "cloudsql.users.update"
		e["reference"] = "https://docs.cloud.google.com/sql/docs/postgres/audit-logging"
		e["rotation_performed"] = false
		e["sql_password_update_performed"] = false
		e["managed_rotation_relationship"] = "Audit configuration at this resource scope only. No active rotation, eligible secret, selected SQL target or observed password update is implied; SQL grant/target project may differ from the secret's project. Secret Manager EnableManagedRotation has a separate Admin Activity event."
	}
	return rows
}
