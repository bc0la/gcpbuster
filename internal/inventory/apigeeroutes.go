package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/bc0la/gcpbuster/internal/secretmatch"
	"regexp"
	"strings"
)

var apigeeBasePathSegment = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,255}$`)
var apigeeReadableSegment = regexp.MustCompile(`^[a-z][a-z_-]{0,23}$|^v[0-9]{1,3}$`)

// SafeApigeeBasePathLiteral is a deliberately narrow display whitelist, not a
// proof that arbitrary path text is nonsecret. Complex/token-shaped paths keep
// only their digest. Shared credential patterns supplement the whitelist.
func SafeApigeeBasePathLiteral(path string) bool {
	if path == "/" {
		return true
	}
	if len(path) > 2048 || !strings.HasPrefix(path, "/") || len(secretmatch.Text([]byte(path), "")) != 0 || appEngineCredentialPattern.MatchString(path) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 64 {
		return false
	}
	for _, part := range parts {
		if !apigeeReadableSegment.MatchString(part) || appEngineSensitiveName.MatchString(part) {
			return false
		}
	}
	return true
}

// HTTPProxyConnection/BasePath is inbound routing configuration, not the
// TargetEndpoint backend URL. Literal paths may contain secrets, so hash them.
// https://docs.cloud.google.com/apigee/docs/api-platform/reference/api-proxy-configuration-reference
func apigeeBasePathProjection(endpoint *apigeeXMLNode) Object {
	unknown := Object{"status": "unknown"}
	if endpoint.name != "ProxyEndpoint" {
		return unknown
	}
	var connection, base *apigeeXMLNode
	for _, child := range endpoint.children {
		if child.name == "HTTPProxyConnection" {
			if connection != nil {
				return unknown
			}
			connection = child
		}
	}
	if connection == nil || len(connection.attrs) != 0 {
		return unknown
	}
	for _, child := range connection.children {
		if child.name == "BasePath" {
			if base != nil {
				return unknown
			}
			base = child
		}
	}
	if base == nil || len(base.children) != 0 || len(base.attrs) != 0 {
		return unknown
	}
	path := strings.TrimSpace(base.text)
	if len(base.text) > 2048 || len(path) == 0 || !strings.HasPrefix(path, "/") {
		return unknown
	}
	count := 0
	if path != "/" {
		for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			if !apigeeBasePathSegment.MatchString(part) || part == "." || part == ".." {
				return unknown
			}
			count++
		}
	}
	if count > 64 {
		return unknown
	}
	digest := sha256.Sum256([]byte(path))
	out := Object{"status": "explicit_literal_path", "path_digest": hex.EncodeToString(digest[:]), "segment_count": count, "root_path": path == "/", "path_display": "redacted_complex_or_sensitive"}
	if SafeApigeeBasePathLiteral(path) {
		out["base_path"] = path
		out["path_display"] = "bounded_readable_literal"
	}
	return out
}
