package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestEffectiveFirewallEvidenceRegionalFamilyAndRedaction(t *testing.T) {
	n := "//compute.googleapis.com/projects/demo/global/networks/default"
	raw := inventory.Object{"network": n, "status": "observed", "scope": "regional_global_and_hierarchical", "region": "us-east1", "regional_policy_coverage": "observed_response", "classic_rule_count": 0, "policy_count": 1, "hierarchical_policy_count": 0, "network_policy_count": 0, "regional_policy_count": 1, "effective_admission": "unknown", "policy_rule_candidates": []any{inventory.Object{"policy_index": 0, "policy_type": "NETWORK_REGIONAL", "rule_priority": 1, "action": "deny", "ip_family": 4, "target_match": "all_instances_on_observed_network", "source_match": "explicit_world_prefix", "layer4_configs": []any{inventory.Object{"ipProtocol": "tcp", "ports": []any{"443"}}}, "description": "SENTINEL"}}, "description": "SENTINEL"}
	got := effectiveFirewallContextEvidence(raw, n, "us-east1", "4")
	if got["status"] != "observed" || len(arr(got["policy_rule_candidates"])) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENTINEL") {
		t.Fatal("source retained")
	}
	if effectiveFirewallContextEvidence(raw, n, "us-west1", "4")["status"] != "unknown" {
		t.Fatal("region mismatch")
	}
	if len(arr(effectiveFirewallContextEvidence(raw, n, "us-east1", "6")["policy_rule_candidates"])) != 0 {
		t.Fatal("family mismatch")
	}
	a := inventory.NewAsset("//compute.googleapis.com/projects/demo/zones/us-east1-b/instances/web", "compute.googleapis.com/Instance", inventory.Object{"name": "web", "networkInterfaces": []any{inventory.Object{"network": "projects/demo/global/networks/default", "subnetwork": "projects/demo/regions/us-east1/subnetworks/subnet", "accessConfigs": []any{inventory.Object{"natIP": "203.0.113.2"}}}}, "_gcpbusterComputeIngressContext": inventory.Object{"status": "configured_candidates", "effective_admission": "unknown", "matches": []any{}, "effective_policy_contexts": []any{inventory.Object{"interface_index": 0, "network": n, "external_address_family": 4, "context": raw}}}})
	projected := computeIngressContextEvidence(a)
	contexts := arr(projected["effective_policy_contexts"])
	if len(contexts) != 1 || len(arr(obj(obj(contexts[0])["context"])["policy_rule_candidates"])) != 1 {
		t.Fatal(projected)
	}
	raw["status"] = "ambiguous"
	if len(arr(effectiveFirewallContextEvidence(raw, n, "us-east1", "4")["policy_rule_candidates"])) != 0 {
		t.Fatal("ambiguous policies retained candidates")
	}
	raw["status"] = "observed"
	obj(arr(raw["policy_rule_candidates"])[0])["policy_index"] = 1
	if len(arr(effectiveFirewallContextEvidence(raw, n, "us-east1", "4")["policy_rule_candidates"])) != 0 {
		t.Fatal("out-of-range policy retained")
	}
}
