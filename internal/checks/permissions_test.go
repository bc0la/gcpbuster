package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestPermissionRisksBoundRoleEvidence(t *testing.T) {
	a := inventory.NewAsset("test", inventory.PermissionGrantType, inventory.Object{"principal": "user:review@example.invalid", "roles": []any{"roles/custom"}, "permissions": []any{"iam.serviceAccounts.getAccessToken", "storage.objects.get", "invented.service.exploit"}})
	r := permissionRisks(a, time.Now())
	if len(r) != 2 {
		t.Fatalf("expected IAM and storage groups: %+v", r)
	}
	for _, x := range r {
		if x.Evidence["principal"] != "user:review@example.invalid" || x.Evidence["catalog_sha256"] == "" || x.Severity != "high" {
			t.Fatal(x)
		}
	}
	a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
	for _, x := range permissionRisks(a, time.Now()) {
		if x.Severity != "medium" {
			t.Fatal("conditional grant overclaimed", x)
		}
	}
}
func TestPermissionCombinationNeedsAllParts(t *testing.T) {
	a := inventory.NewAsset("test", inventory.PermissionGrantType, inventory.Object{"permissions": []any{"run.jobs.run"}})
	for _, x := range permissionCombinations(a, time.Now()) {
		if strings.Contains(strings.Join(x.Evidence["matched_permissions"].([]string), ","), "run.jobs.runWithOverrides") {
			t.Fatal("missing permission inferred")
		}
	}
	a.Resource.Data["permissions"] = []any{"run.jobs.run", "run.jobs.runWithOverrides"}
	found := false
	for _, x := range permissionCombinations(a, time.Now()) {
		matches := x.Evidence["matched_permissions"].([]string)
		if len(matches) == 2 && matches[0] == "run.jobs.run" && matches[1] == "run.jobs.runWithOverrides" {
			found = true
		}
	}
	if !found {
		t.Fatal("combination missed")
	}
}
