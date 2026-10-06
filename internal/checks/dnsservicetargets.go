package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
)

var dnsServiceEvidenceResource = regexp.MustCompile(`^//(run|apigateway)\.googleapis\.com/projects/([A-Za-z0-9_-]+)/locations/[a-z][a-z0-9-]*/(services|gateways)/[A-Za-z0-9_-]+$`)
var dnsApplicationEvidenceResource = regexp.MustCompile(`^//appengine\.googleapis\.com/apps/([A-Za-z0-9_-]+)$`)
var dnsEvidenceRecord = regexp.MustCompile(`^//dns\.googleapis\.com/projects/([A-Za-z0-9_-]+)/managedZones/[A-Za-z0-9_-]+/rrsets/([^/]+)/([^/]+)$`)

func dnsObservedServiceEvidence(a inventory.Asset, target string) inventory.Object {
	out := inventory.Object{"status": "unknown", "assessment": "No verified metadata match supplied; missing or conflicting inventory does not establish resource deletion, absence or reclaimability."}
	marker := obj(val(a, "_gcpbusterObservedServiceTarget"))
	if marker["status"] == "ambiguous" {
		out["status"] = "ambiguous"
		return out
	}
	if marker["status"] != "matched" || marker["basis"] != "exact_same_project_observed_hostname_metadata" {
		return out
	}
	host, valid := inventory.DNSLookupName(s(marker["host"]))
	if !valid || host != target {
		return out
	}
	resource, typ := s(marker["resource"]), s(marker["resource_type"])
	record := dnsEvidenceRecord.FindStringSubmatch(a.Name)
	if record == nil || record[2] != s(val(a, "name")) || s(val(a, "zoneVisibility")) != "public" {
		return out
	}
	namedTarget, valid := inventory.DNSLookupName(record[3])
	if !valid || namedTarget != target {
		return out
	}
	good := false
	if m := dnsServiceEvidenceResource.FindStringSubmatch(resource); m != nil {
		good = m[2] == record[1] && ((m[1] == "run" && m[3] == "services" && typ == "run.googleapis.com/Service") || (m[1] == "apigateway" && m[3] == "gateways" && typ == "apigateway.googleapis.com/Gateway"))
	}
	if m := dnsApplicationEvidenceResource.FindStringSubmatch(resource); m != nil && typ == "appengine.googleapis.com/Application" {
		good = m[1] == record[1]
	}
	if !good {
		return out
	}
	out["status"] = "matched"
	out["resource"] = resource
	out["resource_type"] = typ
	out["assessment"] = "Exact hostname matches independently observed same-project service metadata. A nonresolving DNS target is therefore not evidence that the configured service was deleted. Snapshot freshness, DNS configuration, ingress, authentication and runtime availability remain unverified; no takeover or ownership-control proof."
	return out
}
