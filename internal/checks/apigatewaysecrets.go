package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"math"
	"time"
)

func apiGatewaySecrets(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "apigateway.googleapis.com/ApiConfig" {
		return nil
	}
	var out []Result
	rules := map[string]bool{"private_key": true, "google_api_key": true, "google_oauth_access_token": true, "github_token": true, "aws_access_key_id": true, "slack_token": true, "credential_assignment": true, "url_credentials": true}
	for _, entry := range arr(a.Resource.Data["_gcpbusterSecretCandidates"]) {
		m := obj(entry)
		rule := s(m["rule"])
		doc, dok := gatewaySecretInteger(m["documentIndex"])
		line, lok := gatewaySecretInteger(m["line"])
		if !rules[rule] || !dok || !lok || doc < 0 || doc >= 32 || line < 1 {
			continue
		}
		out = append(out, Result{"high", "Potential plaintext secret in API Gateway configuration source", inventory.Object{"document_index": doc, "line": line, "rule": rule, "value": "[REDACTED]", "assessment": "heuristic source candidate; not validated or used"}, "Review the source securely and rotate confirmed exposed credentials; use managed secret references where supported."})
	}
	return out
}

func gatewaySecretInteger(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		if n >= 0 && n <= 1<<30 && math.Trunc(n) == n {
			return int(n), true
		}
	}
	return 0, false
}
