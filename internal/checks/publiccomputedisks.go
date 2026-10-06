package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var computeDiskGrantResource = regexp.MustCompile(`^//compute\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/(global|regions/[a-z][a-z0-9-]*)/(images|snapshots)/[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// publicComputeDiskCapabilities examines source-use permissions, not generic
// metadata reads or role names. disks.insert documents these exact permissions
// on sourceImage/sourceSnapshot; creation and content access have prerequisites.
// https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/insert
func publicComputeDiskCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType {
		return nil
	}
	m := computeDiskGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil {
		return nil
	}
	// CAI documents regional snapshots under the same Snapshot asset type,
	// but does not document regional images.
	// https://docs.cloud.google.com/asset-inventory/docs/asset-names
	if m[1] != "global" && m[2] != "snapshots" {
		return nil
	}
	kind, typ, permission := "image", "compute.googleapis.com/Image", "compute.images.useReadOnly"
	if m[2] == "snapshots" {
		kind, typ, permission = "snapshot", "compute.googleapis.com/Snapshot", "compute.snapshots.useReadOnly"
	}
	if s(val(a, "resourceType")) != typ {
		return nil
	}
	principal := s(val(a, "principal"))
	if principal != "allUsers" && principal != "allAuthenticatedUsers" {
		return nil
	}
	permitted := false
	for _, p := range arr(val(a, "permissions")) {
		if s(p) == permission {
			permitted = true
		}
	}
	if !permitted {
		return nil
	}
	audience := "all users"
	audienceDetail := "The binding names allUsers; this is not proof that an anonymous caller can invoke Compute APIs."
	if principal == "allAuthenticatedUsers" {
		audience = "any Google-authenticated identity"
		audienceDetail = "allAuthenticatedUsers includes identities outside the organization but is not anonymous access."
	}
	conditionStatus := "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		conditionStatus = "condition supplied; expression was not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			conditionStatus = "malformed condition evidence; effective applicability is unknown"
		}
	}
	return result("medium", "Compute "+kind+" grants source-use capability to "+audience, "Review whether broad sharing of this image or snapshot is intentional. Restrict unintended grants after evaluating conditions and other controls; do not create disks, VMs, exports or copies as a test.", inventory.Object{"resource": val(a, "resource"), "resource_type": typ, "principal": principal, "roles": val(a, "roles"), "permission": permission, "condition": val(a, "condition"), "condition_status": conditionStatus, "audience": audienceDetail, "assessment": "Configured direct resource binding resolved from role definitions only. Source-use permission is not metadata-only get/list, but does not by itself establish disk/VM creation, copying, downloading or filesystem access. Destination creation permissions, encryption requirements, deny, service perimeter, organization restrictions and conditions are unresolved. No disk, image, snapshot or VM was created, restored, attached, exported or read for contents. Sensitive data and effective access were not established. Inherited project/folder/organization grants and unassigned role definitions are not expanded by this indicator."})
}
