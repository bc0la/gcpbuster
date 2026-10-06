package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

const ManagedRotationPrerequisiteType = "gcpbuster.googleapis.com/ManagedRotationPrerequisite"

var rotationSecretName = regexp.MustCompile(`^//secretmanager\.googleapis\.com/projects/([0-9]+)/locations/([a-z][a-z0-9-]*)/secrets/([A-Za-z0-9_-]+)$`)
var rotationUID = regexp.MustCompile(`^principal://secretmanager\.googleapis\.com/projects/([0-9]+)/uid/locations/([a-z][a-z0-9-]*)/secrets/([A-Za-z0-9_-]+)$`)
var rotationAncestor = regexp.MustCompile(`^(projects|folders|organizations)/[0-9]+$`)
var rotationSQLProject = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+$`)

func rotationHasPermission(a inventory.Asset, wanted string) bool {
	for _, p := range inventory.List(a.Resource.Data["permissions"]) {
		if inventory.Str(p) == wanted {
			return true
		}
	}
	return false
}

func rotationScope(scope string) string {
	return strings.TrimPrefix(scope, "//cloudresourcemanager.googleapis.com/")
}

// ManagedRotationPrerequisiteAssets correlates configured allow-policy evidence,
// not effective authorization. Separate SQL grants may contribute permissions
// only on the same exact project scope. Their conditions remain independent,
// unevaluated evidence, not an assertion that both are simultaneously usable.
func ManagedRotationPrerequisiteAssets(assets []inventory.Asset) []inventory.Asset {
	var out []inventory.Asset
	seen := map[string]bool{}
	listGrants := map[string][]inventory.Asset{}
	for _, a := range assets {
		if a.Type == inventory.PermissionGrantType && rotationHasPermission(a, "cloudsql.users.list") {
			key := inventory.Str(a.Resource.Data["principal"]) + "\x00" + rotationScope(inventory.Str(a.Resource.Data["resource"]))
			listGrants[key] = append(listGrants[key], a)
		}
	}
	for _, secret := range assets {
		if secret.Type != "secretmanager.googleapis.com/Secret" || inventory.Str(secret.Resource.Data["secretType"]) != "CLOUD_SQL_DB_CREDENTIALS" {
			continue
		}
		parts := rotationSecretName.FindStringSubmatch(secret.Name)
		uid := inventory.Str(inventory.Get(secret.Resource.Data, "policyMember", "iamPolicyUidPrincipal"))
		identity := rotationUID.FindStringSubmatch(uid)
		if len(parts) != 4 || parts[2] == "global" || len(identity) != 4 || identity[1] != parts[1] || identity[2] != parts[2] || inventory.Str(secret.Resource.Data["name"]) != strings.TrimPrefix(secret.Name, "//secretmanager.googleapis.com/") || (secret.Resource.Location != "" && secret.Resource.Location != parts[2]) {
			continue
		}
		conflict := false
		for _, other := range assets {
			if other.Type == secret.Type && other.Name == secret.Name && (inventory.Str(other.Resource.Data["secretType"]) != "CLOUD_SQL_DB_CREDENTIALS" || inventory.Str(inventory.Get(other.Resource.Data, "policyMember", "iamPolicyUidPrincipal")) != uid) {
				conflict = true
			}
		}
		if conflict {
			continue
		}
		scopes := map[string]bool{secret.Name: true, "projects/" + parts[1]: true}
		for _, ancestor := range secret.Ancestors {
			if rotationAncestor.MatchString(ancestor) {
				scopes[ancestor] = true
			}
		}
		for _, caller := range assets {
			if caller.Type != inventory.PermissionGrantType || !rotationHasPermission(caller, "secretmanager.secrets.enableManagedRotation") || !scopes[rotationScope(inventory.Str(caller.Resource.Data["resource"]))] || inventory.Str(caller.Resource.Data["principal"]) == "" {
				continue
			}
			for _, sql := range assets {
				if sql.Type != inventory.PermissionGrantType || inventory.Str(sql.Resource.Data["principal"]) != uid || !rotationHasPermission(sql, "cloudsql.users.update") {
					continue
				}
				// The documented project grant is assessable. Other scope forms
				// remain in generic grant reports, not a guessed SQL target.
				sqlScope := rotationScope(inventory.Str(sql.Resource.Data["resource"]))
				if !rotationSQLProject.MatchString(sqlScope) {
					continue
				}
				for _, listGrant := range listGrants[uid+"\x00"+sqlScope] {
					key := secret.Name + "\x00" + caller.Name + "\x00" + sql.Name + "\x00" + listGrant.Name
					if seen[key] {
						continue
					}
					seen[key] = true
					digest := sha256.Sum256([]byte(key))
					data := inventory.Object{"secret": secret.Name, "secret_type": "CLOUD_SQL_DB_CREDENTIALS", "built_in_uid_principal": uid, "managed_rotation_state": inventory.Get(secret.Resource.Data, "rotation", "managedRotationStatus", "state"), "caller_principal": caller.Resource.Data["principal"], "caller_grant_resource": caller.Resource.Data["resource"], "caller_roles": caller.Resource.Data["roles"], "caller_condition": caller.Resource.Data["condition"], "sql_grant_resource": sql.Resource.Data["resource"], "sql_roles": sql.Resource.Data["roles"], "sql_condition": sql.Resource.Data["condition"], "sql_permissions": []any{"cloudsql.users.list", "cloudsql.users.update"}}
					data["sql_list_grant_resource"] = listGrant.Resource.Data["resource"]
					data["sql_list_roles"] = listGrant.Resource.Data["roles"]
					data["sql_list_condition"] = listGrant.Resource.Data["condition"]
					data["sql_update_grant"] = sql.Name
					data["sql_list_grant"] = listGrant.Name
					data["sql_permission_composition"] = "Same exact UID principal and project grant scope; independent conditions are not evaluated or merged."
					a := inventory.NewAsset("//gcpbuster.googleapis.com/managed-rotation-prerequisite/"+hex.EncodeToString(digest[:]), ManagedRotationPrerequisiteType, data)
					a.Ancestors = secret.Ancestors
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func managedRotationPrerequisite(a inventory.Asset, _ time.Time) []Result {
	evidence := inventory.Object{}
	for k, v := range a.Resource.Data {
		evidence[k] = v
	}
	evidence["caller_permission"] = "secretmanager.secrets.enableManagedRotation"
	evidence["assessment"] = "Configured prerequisite composition only: eligible regional secret type, exact built-in UID principal SQL user-management grant, and an observed caller enableManagedRotation grant on the secret or named ancestor. Initial one-shot enablement availability, conditions, deny policies, principal access boundaries, effective authorization, supported engine/target user, network reachability and database-user privileges remain unverified. ACTIVE/INACTIVE metadata does not prove initial enablement availability. No rotation, SQL password reset, payload read or database connection was attempted."
	evidence["reference"] = "https://docs.cloud.google.com/secret-manager/regional-secrets/set-up-automatic-rotation-for-cloudsql-secrets-rs"
	return result("medium", "Managed rotation has configured delegated Cloud SQL password-update prerequisites", "Review the caller's enableManagedRotation grant and the exact secret UID's project SQL grant together. Narrow unnecessary capabilities and independently verify intended target, initial enablement state and effective controls; do not invoke rotation to validate this finding.", evidence)
}
