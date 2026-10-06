package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestDNSObservedServiceEvidenceScopeAndUnknown(t *testing.T) {
	a := inventory.NewAsset("//dns.googleapis.com/projects/demo/managedZones/z/rrsets/app.example./api.example", "dns.googleapis.com/ResourceRecordSet", inventory.Object{"name": "app.example.", "type": "CNAME", "target": "api.example", "targetStatus": "address_not_found", "zoneVisibility": "public"})
	marker := inventory.Object{"status": "matched", "basis": "exact_same_project_observed_hostname_metadata", "host": "api.example", "resource": "//run.googleapis.com/projects/demo/locations/us-central1/services/app", "resource_type": "run.googleapis.com/Service"}
	a.Resource.Data["_gcpbusterObservedServiceTarget"] = marker
	if dnsObservedServiceEvidence(a, "api.example")["status"] != "matched" {
		t.Fatal("valid match rejected")
	}
	if len(dnsDangling(a, time.Time{})) != 1 {
		t.Fatal("metadata match changed DNS finding")
	}
	for _, resource := range []string{"//run.googleapis.com/projects/foreign/locations/us-central1/services/app", "https://evil.example/secret", "//appengine.googleapis.com/apps/foreign"} {
		marker["resource"] = resource
		if dnsObservedServiceEvidence(a, "api.example")["status"] != "unknown" {
			t.Fatal(resource)
		}
	}
	marker["resource"] = "//run.googleapis.com/projects/demo/locations/us-central1/services/app"
	marker["host"] = "different.example"
	if dnsObservedServiceEvidence(a, "api.example")["status"] != "unknown" {
		t.Fatal("target mismatch")
	}
}
