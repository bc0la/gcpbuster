package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func storageAnonymousAccess(a inventory.Asset, _ time.Time) []Result {
	if !b(val(a, "anonymous")) || s(val(a, "requestAuthentication")) != "none" || !b(val(a, "accessConfirmed")) {
		return nil
	}
	operation := s(val(a, "operation"))
	if operation != "list" && operation != "object_read" {
		return nil
	}
	title := "Cloud Storage object readable without authentication"
	if operation == "list" {
		title = "Cloud Storage bucket accepts anonymous object listing"
	}
	return result("high", title, "Remove unintended public IAM/ACL grants and enforce public access prevention where appropriate. Reassess intentionally public data separately.", inventory.Object{"operation": operation, "http_status": val(a, "httpStatus"), "prefix_restricted": val(a, "prefixRestricted"), "assessment": "GET succeeded with no Authorization header, cookies or followed redirects; results apply to tested requests only"})
}

func storageContentSecrets(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "matches")) {
		m := obj(v)
		if s(m["rule"]) == "" {
			continue
		}
		out = append(out, Result{"high", "Potential credential in Cloud Storage object or workload-source content", inventory.Object{"rule": m["rule"], "line": m["line"], "archive_file": m["file"], "source_resource": val(a, "resource"), "origin_resource": val(a, "originResource"), "value": "[REDACTED]", "content_scan_complete": val(a, "complete"), "assessment": "pattern match only; credential validity not tested"}, "Inspect the identified location securely, rotate exposed credentials, and remove secrets from source, artifacts and storage objects."})
	}
	return out
}
