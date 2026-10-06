package inventory

import (
	"reflect"
	"strings"
)

// CorrelateStorageControls joins existing metadata to exact bucket grants only.
// It never expands project grants into buckets or resolves inherited org policy.
func CorrelateStorageControls(snap *Snapshot) {
	controls := map[string]Object{}
	conflicts := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != "storage.googleapis.com/Bucket" {
			continue
		}
		name := strings.TrimPrefix(a.Name, "//storage.googleapis.com/")
		if name == a.Name || !bucketNamePattern.MatchString(name) || Str(a.Resource.Data["name"]) != name {
			continue
		}
		selected := Object{"bucket": a.Name, "scope": "exact_bucket_metadata", "status": "observed", "public_access_prevention": "unknown"}
		if pap, ok := Get(a.Resource.Data, "iamConfiguration", "publicAccessPrevention").(string); ok && (pap == "enforced" || pap == "inherited") {
			selected["public_access_prevention"] = pap
		}
		if ubla, ok := Get(a.Resource.Data, "iamConfiguration", "uniformBucketLevelAccess", "enabled").(bool); ok {
			selected["uniform_bucket_level_access"] = ubla
		}
		if previous, exists := controls[a.Name]; exists && !reflect.DeepEqual(previous, selected) {
			conflicts[a.Name] = true
		}
		controls[a.Name] = selected
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != PermissionGrantType || Str(a.Resource.Data["resourceType"]) != "storage.googleapis.com/Bucket" {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterStorageControls")
		resource := Str(a.Resource.Data["resource"])
		if conflicts[resource] {
			a.Resource.Data["_gcpbusterStorageControls"] = Object{"bucket": resource, "scope": "exact_bucket_metadata", "status": "conflicting", "public_access_prevention": "unknown"}
		} else if selected := controls[resource]; selected != nil {
			a.Resource.Data["_gcpbusterStorageControls"] = selected
		}
	}
}
