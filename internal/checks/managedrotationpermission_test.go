package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestManagedRotationPermissionImpactOnly(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"permissions": []any{"secretmanager.secrets.enableManagedRotation"}, "principal": "user:review@example.test", "resource": "projects/demo"})
	got := permissionRisks(a, time.Time{})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatal(got)
	}
	a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
	got = permissionRisks(a, time.Time{})
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatal("conditional impact treated as effective", got)
	}
}
