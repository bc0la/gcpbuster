package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
)

func apigeeBasePathEvidence(raw any) inventory.Object {
	d := obj(raw)
	count, ok := apigeeStepCount(d["segment_count"])
	root, valid := d["root_path"].(bool)
	if d["status"] != "explicit_literal_path" || !apigeePolicyDigest.MatchString(s(d["path_digest"])) || !ok || count > 64 || !valid || root != (count == 0) {
		return inventory.Object{"status": "unknown"}
	}
	out := inventory.Object{"status": "explicit_literal_path", "path_digest": d["path_digest"], "segment_count": count, "root_path": root, "path_display": "redacted_complex_or_sensitive", "assessment": "Explicit inbound BasePath from this observed proxy-revision bundle only. Only bounded readable literal paths are displayed after conservative credential screening; complex/token-shaped paths retain digest only. Environment/hostname attachment, routing conflicts, current reachability and authorization are not established; no URL was requested. Missing, wildcard, malformed or duplicate paths remain unknown."}
	path := s(d["base_path"])
	digest := sha256.Sum256([]byte(path))
	segments := 0
	if path != "/" {
		segments = len(strings.Split(strings.TrimPrefix(path, "/"), "/"))
	}
	if d["path_display"] == "bounded_readable_literal" && inventory.SafeApigeeBasePathLiteral(path) && hex.EncodeToString(digest[:]) == d["path_digest"] && segments == count && root == (path == "/") {
		out["base_path"] = path
		out["path_display"] = "bounded_readable_literal"
	}
	return out
}
