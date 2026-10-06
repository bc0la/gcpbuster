package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestApigeeProductSelfServiceExplicitConfiguration(t *testing.T) {
	digest := strings.Repeat("a", 64)
	a := inventory.NewAsset("//apigee.googleapis.com/organizations/demo/apiproductObservations/"+digest, inventory.ApigeeAPIProductType, inventory.Object{"organization": "organizations/demo", "product_digest": digest, "projection_complete": true, "access": "public", "approval_type": "auto"})
	if len(apigeeProductSelfService(a, time.Time{})) != 1 {
		t.Fatal("missing explicit observation")
	}
	for _, change := range []inventory.Object{{"access": "private"}, {"approval_type": "manual"}, {"projection_complete": false}, {"organization": "organizations/foreign"}, {"approval_type": nil}} {
		d := inventory.Object{}
		for k, v := range a.Resource.Data {
			d[k] = v
		}
		for k, v := range change {
			d[k] = v
		}
		bad := a
		bad.Resource.Data = d
		if len(apigeeProductSelfService(bad, time.Time{})) != 0 {
			t.Fatal(change)
		}
	}
}
