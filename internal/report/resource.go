package report

import (
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"strings"
)

// resourceCandidateSQL projects only reviewed provenance, never full secret
// details. The byte bound is checked before SQLite returns a field to Go.
const resourceCandidateSQL = `CASE WHEN resource_name LIKE '//%.googleapis.com/%' AND resource_name NOT LIKE '//gcpbuster.googleapis.com/%' AND instr(resource_name,'/permission-analysis/')=0 AND instr(resource_name,'/upstream-analysis')=0 AND instr(resource_name,'/inherited-audit-config')=0 AND instr(resource_name,'/group-iam/')=0 AND instr(resource_name,'/workload-grants/')=0 THEN '' ELSE CASE WHEN json_valid(detail_json) THEN CASE
 WHEN module IN ('secrets_scan','configuration_plaintext') AND json_type(detail_json,'$.evidence.source')='text' AND length(CAST(json_extract(detail_json,'$.evidence.source') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.source')
 WHEN json_extract(detail_json,'$.asset_type') IN ('gcpbuster.googleapis.com/PermissionGrant','gcpbuster.googleapis.com/ArtifactUpstreams','gcpbuster.googleapis.com/InheritedAuditConfig') AND json_type(detail_json,'$.evidence.resource')='text' AND length(CAST(json_extract(detail_json,'$.evidence.resource') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.resource')
 WHEN json_extract(detail_json,'$.asset_type')='gcpbuster.googleapis.com/WorkloadIdentityGrant' AND json_type(detail_json,'$.evidence.workload')='text' AND length(CAST(json_extract(detail_json,'$.evidence.workload') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.workload')
 WHEN json_extract(detail_json,'$.asset_type')='gcpbuster.googleapis.com/GroupIAMBinding' THEN json_object('group',CASE WHEN json_type(detail_json,'$.evidence.group')='text' AND length(CAST(json_extract(detail_json,'$.evidence.group') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.group') ELSE '' END,'bound_resource',CASE WHEN json_type(detail_json,'$.evidence.bound_resource')='text' AND length(CAST(json_extract(detail_json,'$.evidence.bound_resource') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.bound_resource') ELSE '' END)
 WHEN json_extract(detail_json,'$.asset_type')='gcpbuster.googleapis.com/ManagedRotationPrerequisite' AND json_type(detail_json,'$.evidence.secret')='text' AND length(CAST(json_extract(detail_json,'$.evidence.secret') AS BLOB))<=8192 THEN json_extract(detail_json,'$.evidence.secret')
 ELSE '' END ELSE '' END END`

func resourceMetadata(resource, provenance string) (name, identity string) {
	if strings.HasPrefix(provenance, "{") {
		var group struct {
			Group         string `json:"group"`
			BoundResource string `json:"bound_resource"`
		}
		if json.Unmarshal([]byte(provenance), &group) == nil {
			provenance = groupResourceCandidate(group.Group, group.BoundResource)
		}
	}
	identity = resource
	if validExportAsset(provenance) {
		identity = provenance
	}
	const marker = "/permission-analysis/"
	if cut := strings.LastIndex(identity, marker); cut >= 0 {
		suffix := identity[cut+len(marker):]
		if len(suffix) == 24 {
			if _, err := hex.DecodeString(suffix); err == nil {
				identity = identity[:cut]
			}
		}
	}
	if !validExportAsset(identity) {
		return "", identity
	}
	// These are resource identifiers, not human-friendly names from labels or
	// titles. The final path segment is the stable service resource ID.
	name = identity[strings.LastIndex(identity, "/")+1:]
	if strings.Contains(identity, "://") && !strings.HasPrefix(identity, "gs://") {
		name = ""
	} // arbitrary URLs are not GCP resource names
	return name, identity
}

func resourceMetadataFromDetail(resource, module, detail string) (string, string) {
	var d struct {
		AssetType string `json:"asset_type"`
		Evidence  struct {
			Source        string `json:"source"`
			Resource      string `json:"resource"`
			Workload      string `json:"workload"`
			BoundResource string `json:"bound_resource"`
			Secret        string `json:"secret"`
			Group         string `json:"group"`
		} `json:"evidence"`
	}
	if json.Unmarshal([]byte(detail), &d) != nil {
		return resourceMetadata(resource, "")
	}
	provenance := ""
	if module == "secrets_scan" || module == "configuration_plaintext" {
		provenance = d.Evidence.Source
	} else {
		switch d.AssetType {
		case "gcpbuster.googleapis.com/PermissionGrant", "gcpbuster.googleapis.com/ArtifactUpstreams", "gcpbuster.googleapis.com/InheritedAuditConfig":
			provenance = d.Evidence.Resource
		case "gcpbuster.googleapis.com/WorkloadIdentityGrant":
			provenance = d.Evidence.Workload
		case "gcpbuster.googleapis.com/GroupIAMBinding":
			provenance = groupResourceCandidate(d.Evidence.Group, d.Evidence.BoundResource)
		case "gcpbuster.googleapis.com/ManagedRotationPrerequisite":
			provenance = d.Evidence.Secret
		}
	}
	return resourceMetadata(resource, provenance)
}

func groupResourceCandidate(group, bound string) string {
	address, err := mail.ParseAddress(group)
	if err == nil && address.Name == "" && address.Address == group && strings.Contains(group, "@") && !strings.ContainsAny(group, "\x00\r\n<>\" ") {
		return "workspace/groups/" + group
	}
	return bound
}
