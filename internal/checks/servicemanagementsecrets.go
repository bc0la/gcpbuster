package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func serviceConfigSecrets(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.ServiceConfigType {
		return nil
	}
	rules := map[string]bool{"private_key": true, "google_api_key": true, "google_oauth_access_token": true, "github_token": true, "aws_access_key_id": true, "slack_token": true, "credential_assignment": true, "url_credentials": true}
	out := []Result{}
	seen := map[string]bool{}
	for _, entry := range arr(val(a, "_gcpbusterSecretCandidates")) {
		rule := s(obj(entry)["rule"])
		if !rules[rule] || seen[rule] {
			continue
		}
		seen[rule] = true
		out = append(out, Result{"high", "Potential plaintext secret in compiled service configuration", inventory.Object{"rollout_history": serviceConfigHistoryEvidence(a), "observed_gateway_pins": serviceConfigPinEvidence(a), "observed_esp_config_pins": serviceConfigESPPinEvidence(a), "rule": rule, "value": "[REDACTED]", "assessment": "Heuristic candidate in returned compiled authentication/backend/HTTP/usage configuration; no credential validation, endpoint requests or raw source inspection."}, "Review the compiled configuration securely and rotate confirmed exposed credentials."})
	}
	return out
}
