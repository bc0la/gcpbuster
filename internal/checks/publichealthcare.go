package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var healthcareGrantResource = regexp.MustCompile(`^//healthcare\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9_-]*/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}(?:/(fhirStores|dicomStores|hl7V2Stores)/[\p{L}\p{N}_.-]{1,256})?$`)

func publicHealthcareCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || !public(s(val(a, "principal"))) {
		return nil
	}
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"healthcare.fhirResources.get", "healthcare.fhirStores.searchResources", "healthcare.dicomStores.dicomWebRead", "healthcare.hl7V2Messages.get", "healthcare.hl7V2Messages.list"}, "Healthcare clinical read", "Project-level clinical-read permission only; applicable datasets/stores and inheritance must be assessed separately. Healthcare REST requires accepted Google OAuth authentication. No clinical resources were requested and neither tokenless access nor data availability is established.")
	}
	m := healthcareGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil {
		return nil
	}
	for _, segment := range strings.Split(s(val(a, "resource")), "/") {
		if segment == "." || segment == ".." {
			return nil
		}
	}
	types := map[string]string{"": "healthcare.googleapis.com/Dataset", "fhirStores": "healthcare.googleapis.com/FhirStore", "dicomStores": "healthcare.googleapis.com/DicomStore", "hl7V2Stores": "healthcare.googleapis.com/Hl7V2Store"}
	if s(val(a, "resourceType")) != types[m[1]] {
		return nil
	}
	perms := map[string]string{"healthcare.fhirResources.get": "fhirStores", "healthcare.fhirStores.searchResources": "fhirStores", "healthcare.dicomStores.dicomWebRead": "dicomStores", "healthcare.hl7V2Messages.get": "hl7V2Stores", "healthcare.hl7V2Messages.list": "hl7V2Stores"}
	seen := map[string]bool{}
	out := []Result{}
	for _, raw := range arr(val(a, "permissions")) {
		permission := s(raw)
		store := perms[permission]
		if store == "" || seen[permission] || (m[1] != "" && m[1] != store) {
			continue
		}
		seen[permission] = true
		severity, status := "high", "no condition supplied on this binding"
		if condition := val(a, "condition"); condition != nil {
			severity, status = "medium", "condition supplied; expression unverified"
			if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
				status = "malformed condition; applicability unknown"
			}
		}
		out = append(out, result(severity, "Healthcare resource grants a clinical read permission to a broad principal", "Review whether the broad clinical-data reader binding is intended; evaluate inherited policies, conditions and organization controls before narrowing it.", inventory.Object{"resource": val(a, "resource"), "resource_type": val(a, "resourceType"), "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": permission, "clinical_store_type": store, "condition": val(a, "condition"), "condition_status": status, "assessment": "Configured role permission only. Cloud Healthcare REST methods require Google OAuth authentication; neither allUsers nor allAuthenticatedUsers proves tokenless access. Resource scope, conditions, deny and service perimeters constrain effective access. No patient records, images or messages were read; data presence and external access remain unverified. Inherited grants are not expanded."})...)
	}
	return out
}
