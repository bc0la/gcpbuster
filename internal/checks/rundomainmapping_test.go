package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestRunDomainMappingNotReadyObservation(t *testing.T) {
	a := inventory.NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/domainMappings/test.cloud.run", "gcpbuster.googleapis.com/RunDomainMapping", inventory.Object{"metadata": inventory.Object{"name": "test.cloud.run", "generation": 2}, "status": inventory.Object{"observedGeneration": 2, "conditions": []any{inventory.Object{"type": "Ready", "status": "False", "message": "PRIVATE_ERROR"}}}})
	got := runDomainMappingStatus(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["generation_alignment"] != "matched" || !strings.Contains(got[0].Evidence["assessment"].(string), "continues to reserve") {
		t.Fatal(got)
	}
	obj(a.Resource.Data["status"])["observedGeneration"] = 1
	if len(runDomainMappingStatus(a, time.Now())) != 0 {
		t.Fatal("stale generation")
	}
	obj(a.Resource.Data["metadata"])["generation"] = int64(2)
	obj(a.Resource.Data["status"])["observedGeneration"] = "1"
	if len(runDomainMappingStatus(a, time.Now())) != 0 {
		t.Fatal("native int64 stale generation")
	}
	delete(obj(a.Resource.Data["status"]), "observedGeneration")
	if got := runDomainMappingStatus(a, time.Now()); len(got) != 1 || got[0].Evidence["generation_alignment"] != "unknown" {
		t.Fatal(got)
	}
	for _, conditions := range []any{[]any{}, []any{inventory.Object{"type": "Ready", "status": "True"}}, []any{inventory.Object{"type": "Ready", "status": false}}, []any{inventory.Object{"type": "Ready", "status": "False"}, inventory.Object{"type": "Ready", "status": "True"}}, []any{inventory.Object{"type": "CertificateProvisioned", "status": "False"}}} {
		obj(a.Resource.Data["status"])["conditions"] = conditions
		if len(runDomainMappingStatus(a, time.Now())) != 0 {
			t.Fatal(conditions)
		}
	}
}
