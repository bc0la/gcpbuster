package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var storageGrantBucket = regexp.MustCompile(`^//storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])$`)

func publicStorageCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || !public(s(val(a, "principal"))) {
		return nil
	}
	permissions := []string{"storage.objects.get", "storage.objects.list", "storage.objects.create", "storage.objects.delete"}
	detail := "Object get reads content/metadata; list enumerates object metadata and is not object-content read. Create alone does not allow overwriting an existing object: overwrite additionally needs delete. Deletion can be constrained by retention/holds and recoverability is independent. Public access prevention can override existing allUsers/allAuthenticatedUsers grants. Uniform bucket-level access disables ACL authorization, not IAM grants. allAuthenticatedUsers requires accepted Google authentication; an allUsers grant can authorize public access only if other controls permit. Conditions, deny and actual object presence are unresolved. No objects were listed, read, created, overwritten or deleted."
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, permissions, "Cloud Storage object", detail+" Project-scope observation only; no individual bucket/object or inherited effective access is asserted.")
	}
	if s(val(a, "resourceType")) != "storage.googleapis.com/Bucket" || !storageGrantBucket.MatchString(s(val(a, "resource"))) {
		return nil
	}
	var out []Result
	actions := map[string]string{"storage.objects.get": "object-read", "storage.objects.list": "object-list", "storage.objects.create": "object-create", "storage.objects.delete": "object-delete"}
	severity, status := "high", "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		severity, status = "medium", "condition supplied; not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	controls := obj(val(a, "_gcpbusterStorageControls"))
	pap, controlStatus := "unknown", "not_correlated"
	if controls["bucket"] == val(a, "resource") && controls["scope"] == "exact_bucket_metadata" {
		controlStatus = s(controls["status"])
		if controlStatus == "observed" {
			if mode := s(controls["public_access_prevention"]); mode == "enforced" || mode == "inherited" {
				pap = mode
			}
		}
	}
	if pap == "enforced" {
		severity = "info"
		detail += " Exact observed bucket metadata explicitly enforces public access prevention, which overrides these broad-principal bindings; this is residual-binding configuration review, not current public-access evidence. Other access paths and control changes remain separate."
	} else if pap == "inherited" {
		detail += " Exact bucket metadata specifies inherited public access prevention; its effective organization-policy state is not resolved and is not assumed disabled."
	}
	for _, permission := range permissions {
		if !has(arr(val(a, "permissions")), permission) {
			continue
		}
		out = append(out, result(severity, "Storage bucket grants "+actions[permission]+" capability to a broad principal", "Review the exact granted object action and intentional public sharing; evaluate public access prevention, conditions and retention controls before changing bindings.", inventory.Object{"resource": val(a, "resource"), "resource_type": "storage.googleapis.com/Bucket", "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": permission, "capability": actions[permission], "condition": val(a, "condition"), "condition_status": status, "public_access_prevention": pap, "bucket_control_evidence": controlStatus, "assessment": "Bucket binding resolved from role definitions only, not effective public access. Optional PAP evidence is joined only from exact bucket metadata, never inferred from the role or UBLA. " + detail})...)
	}
	return out
}
