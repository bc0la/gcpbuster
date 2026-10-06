package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestComputeIngressEvidenceProjectionAndScope(t *testing.T) {
	a := inventory.NewAsset("//compute.googleapis.com/projects/demo/zones/us-east1-b/instances/web", "compute.googleapis.com/Instance", inventory.Object{"name": "web", "networkInterfaces": []any{inventory.Object{"network": "projects/demo/global/networks/default", "accessConfigs": []any{inventory.Object{"natIP": "203.0.113.2"}}}}})
	rule := inventory.Object{"firewall_resource": "//compute.googleapis.com/projects/demo/global/firewalls/world", "interface_index": 0, "network": "//compute.googleapis.com/projects/demo/global/networks/default", "external_address_family": 4, "target_match": "all_instances_in_network", "priority": 1000, "destination_match": "implicit_target_addresses", "allowed": []any{inventory.Object{"IPProtocol": "tcp", "ports": []any{"443"}}}, "description": "SENSITIVE_SENTINEL"}
	route := inventory.Object{"route_resource": "//compute.googleapis.com/projects/demo/global/routes/default-route", "interface_index": 0, "network": "//compute.googleapis.com/projects/demo/global/networks/default", "external_address_family": 4, "priority": 1000, "dest_range": "0.0.0.0/0", "next_hop": "default_internet_gateway", "description": "SENSITIVE_SENTINEL"}
	a.Resource.Data["_gcpbusterComputeIngressContext"] = inventory.Object{"status": "configured_candidates", "effective_admission": "unknown", "matches": []any{rule}, "internet_gateway_routes": []any{route}, "assessment": "SENSITIVE_SENTINEL"}
	got := computeIngressContextEvidence(a)
	if len(arr(got["matches"])) != 1 || len(arr(got["internet_gateway_routes"])) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENSITIVE_SENTINEL") {
		t.Fatal("arbitrary source retained")
	}
	rule["firewall_resource"] = "//compute.googleapis.com/projects/foreign/global/firewalls/world"
	route["interface_index"] = 99
	got = computeIngressContextEvidence(a)
	if len(arr(got["matches"])) != 0 || len(arr(got["internet_gateway_routes"])) != 0 {
		t.Fatal(got)
	}
	rule["firewall_resource"] = "//compute.googleapis.com/projects/demo/global/firewalls/world"
	rule["target_match"] = "SENSITIVE_SENTINEL"
	if len(arr(computeIngressContextEvidence(a)["matches"])) != 0 {
		t.Fatal("unknown enum accepted")
	}
}

func TestComputeIngressEvidenceMalformedPortsAndFamilies(t *testing.T) {
	for _, raw := range []any{[]any{inventory.Object{"IPProtocol": "tcp", "ports": []any{"443-1"}}}, []any{inventory.Object{"IPProtocol": "icmp", "ports": []any{"22"}}}, []any{inventory.Object{"IPProtocol": "SENSITIVE_SENTINEL", "ports": []any{}}}, []any{inventory.Object{"IPProtocol": "tcp", "ports": nil}}} {
		if _, ok := ingressContextAllowed(raw); ok {
			t.Fatal(raw)
		}
	}
	a := inventory.NewAsset("//compute.googleapis.com/projects/demo/zones/us-east1-b/instances/web", "compute.googleapis.com/Instance", inventory.Object{"name": "web", "networkInterfaces": []any{inventory.Object{"network": "projects/demo/global/networks/default", "accessConfigs": []any{inventory.Object{"natIP": "203.0.113.2"}}}}})
	for _, family := range []any{6, 5, "4"} {
		if _, ok := ingressContextNIC(a, inventory.Object{"interface_index": 0, "network": "//compute.googleapis.com/projects/demo/global/networks/default", "external_address_family": family}); ok {
			t.Fatal(family)
		}
	}
}
