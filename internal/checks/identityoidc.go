package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

var identityOIDCName = regexp.MustCompile(`^//identitytoolkit\.googleapis\.com/projects/[0-9]+/(?:tenants/[A-Za-z0-9_-]+/)?oauthIdpConfigs/oidc\.[A-Za-z0-9_.-]+$`)

func identityOIDCResponseType(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/IdentityPlatformOIDCProvider" || !identityOIDCName.MatchString(a.Name) {
		return nil
	}
	if name, ok := val(a, "name").(string); !ok || "//identitytoolkit.googleapis.com/"+name != a.Name {
		return nil
	}
	enabled, known := val(a, "enabled").(bool)
	if !known || !enabled {
		return nil
	}
	if complete, present := a.Resource.Data["projection_complete"]; present {
		if flag, ok := complete.(bool); !ok || !flag {
			return nil
		}
	}
	response := obj(val(a, "responseType"))
	id, known := response["idToken"].(bool)
	if !known || !id {
		return nil
	}
	codeState := "not_supplied"
	if raw, present := response["code"]; present {
		code, ok := raw.(bool)
		if !ok || code {
			return nil
		}
		codeState = "explicitly_false"
	}
	if raw, present := response["token"]; present {
		token, ok := raw.(bool)
		if !ok || token {
			return nil
		}
	}
	return result("info", "Identity Platform OIDC provider requests front-channel ID tokens", "Review whether the configured implicit response type meets application requirements; evaluate code-flow compatibility and provider settings without attempting authentication.", inventory.Object{"enabled": true, "id_token_response": true, "code_response": codeState, "assessment": "Configured OIDC authorization response only: an ID token is requested from the provider authorization endpoint, associated with implicit flow. This supported configuration is not universally unsafe or proof of token leakage, missing client secrets, public signup or authentication bypass. Provider trust, redirect handling and application authorization remain separate. No issuer discovery, token exchange or login was performed; issuer URLs, client identifiers and secret values are not evidence."})
}
