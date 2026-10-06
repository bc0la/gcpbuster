package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strconv"
	"time"
)

var runMappingResource = regexp.MustCompile(`^//run\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9.:-]*/locations/[a-z][a-z0-9-]*/domainMappings/([^/]+)$`)

func runDomainMappingStatus(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/RunDomainMapping" {
		return nil
	}
	m := runMappingResource.FindStringSubmatch(a.Name)
	if m == nil {
		return nil
	}
	domain, valid := inventory.DNSLookupName(m[1])
	if !valid {
		return nil
	}
	if supplied := s(val(a, "metadata", "name")); supplied != "" {
		normalized, ok := inventory.DNSLookupName(supplied)
		if !ok || normalized != domain {
			return nil
		}
	}
	ready := ""
	count := 0
	for _, raw := range arr(val(a, "status", "conditions")) {
		c := obj(raw)
		if s(c["type"]) == "Ready" {
			count++
			ready = s(c["status"])
		}
	}
	if count != 1 || ready != "False" {
		return nil
	}
	match := "unknown"
	g, gok := runMappingGeneration(val(a, "metadata", "generation"))
	o, ook := runMappingGeneration(val(a, "status", "observedGeneration"))
	if gok && ook && g > 0 && o > 0 {
		if g != o {
			return nil
		}
		match = "matched"
	}
	return result("info", "Cloud Run domain mapping has an observed not-ready status", "Review the mapping's route, certificate and DNS configuration through trusted administrative interfaces. Preserve reservations while investigating; do not delete mappings or claim names as a test.", inventory.Object{"ready_status": "False", "generation_alignment": match, "assessment": "Provider condition observation only; current-generation reconciliation is unverified when generation alignment is unknown. This does not establish a missing route, public access, DNS nonresolution, exploitable dangling domain or name reclaimability. A surviving Cloud Run custom-URL mapping continues to reserve its cloud.run name even if the underlying service is deleted; deletion of the mapping is a separate action. No DNS lookup, endpoint probe, deletion or registration was performed."})
}

func runMappingGeneration(raw any) (uint64, bool) {
	switch n := raw.(type) {
	case int64:
		if n > 0 {
			return uint64(n), true
		}
	case string:
		if n != "" && n[0] >= '1' && n[0] <= '9' {
			v, e := strconv.ParseUint(n, 10, 63)
			return v, e == nil && v > 0
		}
	default:
		if v, ok := gatewaySecretInteger(raw); ok && v > 0 {
			return uint64(v), true
		}
	}
	return 0, false
}
