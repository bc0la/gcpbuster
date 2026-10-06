package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
)

func TestServiceConfigESPPinsTypedScopeNotRuntime(t *testing.T) {
	a := inventory.NewAsset("//servicemanagement.googleapis.com/services/example.com/configs/compiled", inventory.ServiceConfigType, inventory.Object{"name": "example.com", "id": "compiled", "producerProjectId": "demo"})
	row := inventory.Object{"workload": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/esp", "workload_type": "compute.googleapis.com/Instance", "vm_status": "RUNNING", "selection": "explicit_fixed_container_declaration", "service": "example.com", "config_id": "compiled"}
	a.Resource.Data["_gcpbusterESPConfigPins"] = []any{row}
	if len(serviceConfigESPPinEvidence(a)) != 1 {
		t.Fatal("missing pin")
	}
	for _, key := range []string{"service", "config_id", "vm_status", "selection", "workload_type", "workload"} {
		old := row[key]
		row[key] = "foreign"
		if len(serviceConfigESPPinEvidence(a)) != 0 {
			t.Fatal(key)
		}
		row[key] = old
	}
	a.Resource.Data["producerProjectId"] = "other"
	if len(serviceConfigESPPinEvidence(a)) != 0 {
		t.Fatal("foreign producer")
	}
}
