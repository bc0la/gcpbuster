package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func alloyDBUserRoles(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.AlloyDBUserType {
		return nil
	}
	for _, raw := range arr(val(a, "databaseRoles")) {
		if role, ok := raw.(string); ok && role == "alloydbsuperuser" {
			return result("info", "AlloyDB user has the managed superuser group role", "Review whether this database principal needs the AlloyDB-managed administrative role; validate ownership and database access separately.", inventory.Object{"database_role": "alloydbsuperuser", "assessment": "Observed managed database role membership, not a Cloud IAM grant or PostgreSQL SUPERUSER attribute. Membership does not prove credentials, network connectivity, successful login, malicious persistence or effective inherited privileges. No SQL was executed."})
		}
	}
	return nil
}
