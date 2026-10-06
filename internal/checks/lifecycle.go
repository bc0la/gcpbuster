package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SecretAliasMetadataType = "gcpbuster.googleapis.com/SecretAliasMetadata"

// SecretAliasAssets correlates only exact resource names. Missing/conflicting
// version evidence remains unknown, never an assertion of deleted data.
func SecretAliasAssets(assets []inventory.Asset) []inventory.Asset {
	versions := map[string]string{}
	conflicts := map[string]bool{}
	aliasTargets := map[string]string{}
	aliasConflicts := map[string]bool{}
	for _, a := range assets {
		if a.Type != "secretmanager.googleapis.com/Secret" {
			continue
		}
		for alias, value := range obj(val(a, "versionAliases")) {
			key := a.Name + "\x00" + alias
			version := s(value)
			if old, exists := aliasTargets[key]; exists && old != version {
				aliasConflicts[key] = true
			}
			aliasTargets[key] = version
		}
	}
	for _, a := range assets {
		if a.Type != "secretmanager.googleapis.com/SecretVersion" {
			continue
		}
		state := s(val(a, "state"))
		if state != "ENABLED" && state != "DISABLED" && state != "DESTROYED" {
			continue
		}
		if old, ok := versions[a.Name]; ok && old != state {
			conflicts[a.Name] = true
		}
		versions[a.Name] = state
	}
	out := []inventory.Asset{}
	seen := map[string]bool{}
	for _, a := range assets {
		if a.Type != "secretmanager.googleapis.com/Secret" || !strings.HasPrefix(a.Name, "//secretmanager.googleapis.com/projects/") {
			continue
		}
		aliases := obj(val(a, "versionAliases"))
		if len(aliases) > 50 {
			continue
		}
		keys := []string{}
		for k := range aliases {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, alias := range keys {
			version := s(aliases[alias])
			id, e := strconv.ParseInt(version, 10, 64)
			if e != nil || id <= 0 || strconv.FormatInt(id, 10) != version || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,62}$`).MatchString(alias) || strings.EqualFold(alias, "latest") || strings.EqualFold(alias, "new") {
				continue
			}
			target := a.Name + "/versions/" + version
			state := versions[target]
			if conflicts[target] || aliasConflicts[a.Name+"\x00"+alias] || state == "" {
				state = "UNKNOWN"
			}
			key := a.Name + "\x00" + alias
			if seen[key] {
				continue
			}
			seen[key] = true
			digest := sha256.Sum256([]byte(key))
			d := inventory.Object{"secret": a.Name, "alias": alias, "version": version, "version_resource": target, "state": state, "aliases_observed_by_get": val(a, "gcpbusterAliasesObserved") == true}
			derived := inventory.NewAsset("//gcpbuster.googleapis.com/secret-alias/"+hex.EncodeToString(digest[:]), SecretAliasMetadataType, d)
			derived.Ancestors = a.Ancestors
			derived.Resource.Location = a.Resource.Location
			out = append(out, derived)
		}
	}
	return out
}

func parsedTime(v any) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s(v))
	return t, err == nil
}

func secretManagerLifecycle(a inventory.Asset, now time.Time) []Result {
	if a.Type == ManagedRotationPrerequisiteType {
		return managedRotationPrerequisite(a, now)
	}
	if a.Type == SecretAliasMetadataType {
		state := s(val(a, "state"))
		if state != "ENABLED" && state != "DISABLED" && state != "DESTROYED" && state != "UNKNOWN" {
			return nil
		}
		severity, title := "info", "Secret version alias is a mutable metadata reference"
		if state == "DISABLED" || state == "DESTROYED" {
			severity, title = "low", "Secret version alias points to a non-enabled observed version"
		}
		return result(severity, title, "Review intended alias targets and principals with secretmanager.secrets.update. Use version pinning where required; independently verify consumers and current metadata before assessing availability or unauthorized changes.", inventory.Object{"secret": val(a, "secret"), "alias": val(a, "alias"), "version": val(a, "version"), "version_resource": val(a, "version_resource"), "observed_state": state, "aliases_observed_by_get": val(a, "aliases_observed_by_get"), "assessment": "Metadata-only mapping and exact-name version correlation. UNKNOWN means missing or conflicting supplied evidence, not a missing version. A configured alias is not evidence of tampering, credential exposure, actual consumer use or effective authorization. No payload was read."})
	}
	if a.Type == "secretmanager.googleapis.com/SecretVersion" {
		if s(val(a, "state")) != "DISABLED" {
			return nil
		}
		if when, ok := parsedTime(val(a, "scheduledDestroyTime")); ok {
			return result("low", "Secret version is disabled but not yet permanently destroyed", "Treat scheduled destruction as a recovery window, not credential revocation. Rotate the underlying credential and review principals able to re-enable versions; validate current state before incident-response decisions.", inventory.Object{"state": "DISABLED", "scheduled_destroy_time": when.UTC().Format(time.RFC3339Nano), "assessment": "Metadata observation; scheduled destruction can be canceled by an authorized principal. No payload was read."})
		}
		return nil
	}
	var out []Result
	// Retrieved expiration is an absolute timestamp even if configured via TTL.
	// A schedule is not evidence that deletion has already happened.
	if expiration, ok := parsedTime(val(a, "expireTime")); ok {
		severity, title := "info", "Secret has scheduled automatic expiration"
		if !expiration.After(now) {
			severity, title = "low", "Secret metadata expiration time has passed"
		}
		out = append(out, Result{severity, title, inventory.Object{"expire_time": expiration.UTC().Format(time.RFC3339Nano), "assessment": "Configured secret expiration deletes the secret and its versions; this may be intentional retention policy. Metadata alone does not prove deletion or revocation of the underlying external credential."}, "Review dependent workloads and the intended retention policy. Refresh past-due metadata before claiming the secret was deleted; rotate or revoke external credentials separately where required."})
	}
	rotation := obj(val(a, "rotation"))
	if s(val(a, "secretType")) == "CLOUD_SQL_DB_CREDENTIALS" {
		state := s(obj(rotation["managedRotationStatus"])["state"])
		if state == "ACTIVE" || state == "INACTIVE" {
			severity, title := "info", "Typed secret reports active managed rotation"
			if state == "INACTIVE" {
				severity, title = "low", "Typed secret reports inactive managed rotation"
			}
			out = append(out, Result{severity, title, inventory.Object{"secret_type": "CLOUD_SQL_DB_CREDENTIALS", "managed_rotation_state": state, "assessment": "Explicit metadata state only. ACTIVE does not establish successful password rotation, intended SQL target, IAM prerequisites or healthy consumers; INACTIVE can be intentional. Error payloads and database credentials were not read."}, "Verify the intended managed-rotation policy, configured database target and built-in identity permissions through authorized operational review. Do not enable or invoke rotation as part of assessment."})
		}
	}
	if key := s(val(a, "customerManagedEncryption", "kmsKeyName")); regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`).MatchString(key) {
		parts := strings.Split(key, "/")
		out = append(out, Result{"info", "Regional secret depends on a customer-managed KMS key", inventory.Object{"kms_key": key, "key_project": parts[1], "key_location": parts[3], "assessment": "Configured encryption dependency only, not evidence of hijacking, inaccessible keys or attacker ownership. Regional secret CMEK changes affect newly added versions, not existing versions; key authorization and availability were not tested."}, "Review the key's ownership, location, lifecycle and the Secret Manager service identity's permissions. Monitor authorized configuration changes and separately revoke exposed underlying credentials."})
	}
	if next, ok := parsedTime(rotation["nextRotationTime"]); ok && next.Before(now.Add(-24*time.Hour)) {
		out = append(out, Result{"medium", "Secret rotation notification time is overdue", inventory.Object{"next_rotation_time": next.UTC().Format(time.RFC3339Nano), "grace_hours": 24, "assessment": "A stale notification schedule is a review indicator, not proof that the credential was not rotated. CAI metadata can lag."}, "Inspect Secret Manager notification delivery and the rotation worker; refresh metadata and verify that new credentials are issued and deployed."})
	}
	// A recurring period without a next time is explicitly supplied but incomplete;
	// it is not interpreted as successful scheduled rotation.
	if s(rotation["rotationPeriod"]) != "" && s(rotation["nextRotationTime"]) == "" {
		out = append(out, Result{"low", "Secret rotation metadata has a period but no next notification time", inventory.Object{"rotation_period": rotation["rotationPeriod"], "assessment": "May be incomplete or stale inventory; no claim of active rotation."}, "Read current secret metadata and verify the intended notification schedule and worker."})
	}
	if len(arr(val(a, "topics"))) > 0 && rotation == nil {
		out = append(out, Result{"low", "Secret has notification topics but no rotation schedule in supplied metadata", inventory.Object{"topic_count": len(arr(val(a, "topics"))), "assessment": "Topics also serve non-rotation events. This is not proof of tampering or absent external/manual rotation."}, "Confirm whether rotation notifications are intended and verify the independently operated rotation workflow."})
	}
	if ttl, err := time.ParseDuration(s(val(a, "versionDestroyTtl"))); err == nil && ttl > 0 {
		out = append(out, Result{"info", "Secret versions use delayed destruction", inventory.Object{"version_destroy_ttl": s(val(a, "versionDestroyTtl")), "assessment": "Recovery feature, not intrinsically insecure; destruction requests leave a period in which authorized principals can restore versions."}, "Account for this recovery window in incident response. Revoke or rotate the actual credential rather than relying only on deleting its stored copy."})
	}
	return out
}

func kmsLifecycle(a inventory.Asset, now time.Time) []Result {
	if a.Type == "cloudkms.googleapis.com/CryptoKeyVersion" {
		if s(val(a, "state")) != "DESTROY_SCHEDULED" {
			return nil
		}
		when, ok := parsedTime(val(a, "destroyTime"))
		if !ok {
			return nil
		}
		return result("low", "KMS key version is scheduled for destruction", "Verify dependencies before permanent destruction and review restore permissions. Scheduled destruction is reversible; never assume that rotation re-encrypts existing data.", inventory.Object{"destroy_time": when.UTC().Format(time.RFC3339Nano), "assessment": "Pending destruction metadata, not proof of malicious activity or completed erasure."})
	}
	if s(val(a, "purpose")) != "ENCRYPT_DECRYPT" || b(val(a, "importOnly")) {
		return nil
	}
	level := s(val(a, "versionTemplate", "protectionLevel"))
	if level != "SOFTWARE" && level != "HSM" {
		return nil
	}
	var out []Result
	if next, ok := parsedTime(val(a, "nextRotationTime")); ok && next.Before(now.Add(-24*time.Hour)) {
		out = append(out, Result{"medium", "KMS automatic rotation time is overdue", inventory.Object{"next_rotation_time": next.UTC().Format(time.RFC3339Nano), "grace_hours": 24, "assessment": "Refresh possibly stale metadata and inspect rotation failures; previous versions remain usable after rotation."}, "Inspect key rotation status, permissions and current metadata; verify that new versions are being created as intended."})
	}
	if s(val(a, "name")) != "" && s(val(a, "createTime")) != "" && s(val(a, "rotationPeriod")) == "" && s(val(a, "nextRotationTime")) == "" {
		out = append(out, Result{"low", "Eligible KMS key has no automatic rotation schedule in supplied metadata", inventory.Object{"purpose": "ENCRYPT_DECRYPT", "protection_level": level, "assessment": "A manual rotation process may exist. No universal rotation interval or re-encryption requirement is inferred."}, "Verify the organization's rotation policy and manual process, or configure an appropriate automatic rotation schedule."})
	}
	return out
}
