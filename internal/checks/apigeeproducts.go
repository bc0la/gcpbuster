package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

func apigeeProductSelfService(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.ApigeeAPIProductType || val(a, "projection_complete") != true || val(a, "access") != "public" || val(a, "approval_type") != "auto" {
		return nil
	}
	org, digest := s(val(a, "organization")), s(val(a, "product_digest"))
	if !regexp.MustCompile(`^organizations/[A-Za-z0-9_-]+$`).MatchString(org) || !apigeePolicyDigest.MatchString(digest) || a.Name != "//apigee.googleapis.com/"+org+"/apiproductObservations/"+digest {
		return nil
	}
	return result("info", "Apigee public API product automatically approves consumer keys", "Review whether automatic product-key approval is intended. Separately review portal enrollment, audiences, product publication and independent proxy/backend authorization.", inventory.Object{"product_digest": digest, "access": "public", "approval_type": "auto", "assessment": "Explicit product configuration only: public visibility and automatic approval of consumer keys when an application registers for this product. This does not establish open portal registration, publication, a usable issued key, deployed proxy access or anonymous invocation. No accounts/apps/keys were created, read or tested."})
}
