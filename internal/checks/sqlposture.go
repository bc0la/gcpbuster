package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strconv"
)

var sqlPostureEngine = regexp.MustCompile(`^(MYSQL|POSTGRES|SQLSERVER)_([0-9]+)(?:_[A-Z0-9]+)*$`)

// sqlConfigurationPosture assesses explicit control-plane settings only.
// Source: gcp-cloud-sql-enum.md (Password, Zone Availability, Data Protection).
// Field/engine semantics: https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances
// and each engine's backup-recovery/configure-pitr documentation. Enhanced
// backups use an associated backup plan, so instance flags alone are inadequate.
func sqlConfigurationPosture(a inventory.Asset) []Result {
	engine := sqlPostureEngine.FindStringSubmatch(s(val(a, "databaseVersion")))
	if len(engine) != 3 {
		return nil
	}
	var out []Result
	primary := s(val(a, "instanceType")) == "CLOUD_SQL_INSTANCE"
	// A conflicting or malformed replication parent cannot establish primary status.
	if raw, exists := a.Resource.Data["masterInstanceName"]; exists {
		parent, ok := raw.(string)
		primary = primary && ok && parent == ""
	}
	if primary && s(val(a, "settings", "availabilityType")) == "ZONAL" {
		out = append(out, Result{"info", "Cloud SQL primary uses zonal availability", inventory.Object{"availability_type": "ZONAL", "assessment": "Review workload availability requirements; development workloads may intentionally use zonal availability. No failover or recovery test was performed."}, "Consider regional availability where the workload requires protection against a zonal outage."})
	}
	if primary && s(val(a, "settings", "backupConfiguration", "backupTier")) == "STANDARD" {
		field := "pointInTimeRecoveryEnabled"
		if engine[1] == "MYSQL" {
			field = "binaryLogEnabled"
		}
		if enabled, ok := val(a, "settings", "backupConfiguration", field).(bool); ok && !enabled {
			out = append(out, Result{"info", "Cloud SQL primary PITR setting explicitly disabled", inventory.Object{"database_version": s(val(a, "databaseVersion")), "field": field, "backup_tier": "STANDARD", "assessment": "Standard-backup primary configuration only; review recovery requirements. Backup success, retained transaction logs and restore capability were not tested."}, "Review whether this primary requires point-in-time recovery and configure the engine-supported option where appropriate."})
		}
	}
	// The reviewed source documents MySQL facets. Do not extend their engine
	// semantics or invent a universal password-length/complexity threshold.
	enabled, ok := val(a, "settings", "passwordValidationPolicy", "enablePasswordPolicy").(bool)
	if engine[1] != "MYSQL" || !ok || !enabled {
		return out
	}
	if disallow, ok := val(a, "settings", "passwordValidationPolicy", "disallowUsernameSubstring").(bool); ok && !disallow {
		out = append(out, Result{"info", "Cloud SQL MySQL password policy does not prohibit username substrings", inventory.Object{"field": "disallowUsernameSubstring", "assessment": "Instance policy setting only; this does not establish any user's current password or override other password controls."}, "Review whether the local-user policy should disallow the username within passwords."})
	}
	major, err := strconv.Atoi(engine[2])
	if err == nil && major >= 8 && sqlExplicitZero(val(a, "settings", "passwordValidationPolicy", "reuseInterval")) {
		out = append(out, Result{"info", "Cloud SQL MySQL password policy has zero password history", inventory.Object{"field": "reuseInterval", "assessment": "Enabled instance policy on MySQL 8 or later; no previous passwords are excluded by this policy setting. Other controls and actual password reuse were not assessed."}, "Review whether a password history requirement is appropriate for local users."})
	}
	return out
}

func sqlExplicitZero(v any) bool {
	switch n := v.(type) {
	case float64:
		return n == 0
	case int:
		return n == 0
	case int64:
		return n == 0
	default:
		return false
	}
}
