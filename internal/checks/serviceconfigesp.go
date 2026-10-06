package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"sort"
)

var espEvidenceVM = regexp.MustCompile(`^//compute\.googleapis\.com/projects/([a-z][a-z0-9-]*)/zones/[a-z][a-z0-9-]*/instances/[a-z][a-z0-9-]*$`)
var espEvidenceService = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+$`)
var espEvidenceConfig = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

func serviceConfigESPPinEvidence(a inventory.Asset) []any {
	service, id := s(val(a, "name")), s(val(a, "id"))
	if a.Type != inventory.ServiceConfigType || !espEvidenceService.MatchString(service) || !espEvidenceConfig.MatchString(id) || a.Name != "//servicemanagement.googleapis.com/services/"+service+"/configs/"+id {
		return nil
	}
	seen := map[string]bool{}
	for _, raw := range arr(val(a, "_gcpbusterESPConfigPins")) {
		row := obj(raw)
		workload := s(row["workload"])
		m := espEvidenceVM.FindStringSubmatch(workload)
		if m == nil || m[1] != s(val(a, "producerProjectId")) || row["service"] != service || row["config_id"] != id || row["workload_type"] != "compute.googleapis.com/Instance" || row["vm_status"] != "RUNNING" || row["selection"] != "explicit_fixed_container_declaration" {
			continue
		}
		seen[workload] = true
	}
	names := []string{}
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []any{}
	for _, name := range names {
		out = append(out, inventory.Object{"workload": name, "selection": "explicit_fixed_container_declaration", "assessment": "Observed running VM metadata declares this explicit fixed ESP configuration. The legacy container declaration may be unused or stale; VM state does not establish guest agent/container execution, image contents, traffic routing, current serving config or effective authentication. Managed rollout, local config files, startup scripts and Cloud Run image-baked configuration are not inferred."})
	}
	return out
}
