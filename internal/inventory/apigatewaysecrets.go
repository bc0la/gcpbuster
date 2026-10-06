package inventory

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

// Scan only returned OpenAPI configuration sources, never references or backend
// responses. Neither caller-controlled filenames nor matched bytes are retained.
func projectAPIGatewaySecrets(raw Object) ([]any, error) {
	var out []any
	docs, ok := raw["openapiDocuments"].([]any)
	if !ok || len(docs) == 0 {
		return nil, fmt.Errorf("OpenAPI source unavailable for secret inspection")
	}
	if len(docs) > 32 {
		return nil, fmt.Errorf("OpenAPI document count exceeds inspection limit")
	}
	remaining := 4 << 20
	partial := false
	for i, entry := range docs {
		encoded, ok := Get(Obj(entry), "document", "contents").(string)
		if !ok || len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(remaining) {
			partial = true
			continue
		}
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(b) > remaining || bytes.IndexByte(b, 0) >= 0 {
			partial = true
			continue
		}
		remaining -= len(b)
		for _, match := range secretmatch.Text(b, "") {
			if len(out) >= 1000 {
				return out, fmt.Errorf("OpenAPI secret candidate limit reached")
			}
			out = append(out, Object{"documentIndex": i, "rule": match.Rule, "line": match.Line})
		}
	}
	if partial {
		return out, fmt.Errorf("some OpenAPI sources were malformed, binary or over the inspection limit")
	}
	return out, nil
}
