package checks

import (
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestAuditLoggingSkipsBindingsOnlySearchResults(t *testing.T) {
	a := inventory.Asset{Type: "cloudresourcemanager.googleapis.com/Project", IAM: inventory.Object{"_gcpbusterBindingsOnly": true}}
	if got := auditLogging(a, time.Now()); len(got) != 0 {
		t.Fatal("search results do not prove missing audit configuration", got)
	}
	a.IAM = inventory.Object{}
	if got := auditLogging(a, time.Now()); len(got) != 1 {
		t.Fatal("complete direct policy should retain existing assessment", got)
	}
}
