package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestDNSRecordSecretsSafeCandidates(t *testing.T) {
	row := inventory.Object{"field": "rrdatas", "record_index": 0, "rule": "github_token", "value": "PRIVATE_SENTINEL"}
	for _, kind := range []string{inventory.DNSRecordSetType, inventory.DNSResponsePolicyRuleType} {
		data := inventory.Object{"_gcpbusterSecretCandidates": []any{row, row, inventory.Object{"field": "rrdatas", "record_index": -1, "rule": "github_token"}, inventory.Object{"field": "PRIVATE_SENTINEL", "record_index": 0, "rule": "github_token"}}}
		if kind == inventory.DNSResponsePolicyRuleType {
			data = inventory.Object{"localData": inventory.Object{"localDatas": []any{data}}}
		}
		got := dnsRecordSecrets(inventory.NewAsset("test", kind, data), time.Now())
		if len(got) != 1 {
			t.Fatal(got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_SENTINEL") {
			t.Fatal(string(b))
		}
	}
}

func TestDNSResponseRulesBoundaries(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		complete bool
		want     int
	}{{"bypassResponsePolicy", true, 1}, {"local", true, 1}, {"unknown", true, 0}, {"both", true, 0}, {"local", false, 0}, {"bypassResponsePolicy", false, 0}} {
		data := inventory.Object{"dnsName": "*.example.test.", "complete": tc.complete, "_gcpbusterPolicyBindings": inventory.Object{"networks": []any{inventory.Object{"networkUrl": "projects/demo/global/networks/default"}}}}
		if tc.mode == "local" || tc.mode == "both" {
			data["localData"] = inventory.Object{"localDatas": []any{inventory.Object{"name": "*.example.test.", "type": "A"}}}
		}
		if tc.mode != "local" {
			data["behavior"] = tc.mode
		}
		a := inventory.NewAsset("test", inventory.DNSResponsePolicyRuleType, data)
		if got := dnsResponseRule(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
		delete(data, "_gcpbusterPolicyBindings")
		if got := dnsResponseRule(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
	for _, record := range []inventory.Object{{"name": "foreign.test.", "type": "A"}, {"name": "example.test.", "type": "NS"}, {"name": "example.test.", "type": "SOA"}} {
		a := inventory.NewAsset("test", inventory.DNSResponsePolicyRuleType, inventory.Object{"dnsName": "example.test.", "complete": true, "localData": inventory.Object{"localDatas": []any{record}}, "_gcpbusterPolicyBindings": inventory.Object{"gkeClusters": []any{inventory.Object{"gkeClusterName": "projects/demo/locations/us-central1/clusters/gke"}}}})
		if got := dnsResponseRule(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
