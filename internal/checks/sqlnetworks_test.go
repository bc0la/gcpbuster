package checks

import (
	"testing"
	"time"
)

func TestSQLAuthorizedNetworkValidity(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, settings, severity string }{
		{"unbounded", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0"}]}`, "high"},
		{"hostbits", `"ipConfiguration":{"authorizedNetworks":[{"value":"192.0.2.1/0"}]}`, "high"},
		{"future-v6", `"ipConfiguration":{"authorizedNetworks":[{"value":"::/0","expirationTime":"2026-10-05T12:00:01Z"}]}`, "high"},
		{"expired", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0","expirationTime":"2026-10-05T11:59:59Z"}]}`, ""},
		{"boundary", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0","expirationTime":"2026-10-05T12:00:00Z"}]}`, ""},
		{"offset-boundary", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0","expirationTime":"2026-10-05T07:00:00-05:00"}]}`, ""},
		{"invalid-expiration", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0","expirationTime":"bad"}]}`, "medium"},
		{"wrong-expiration-type", `"ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0","expirationTime":false}]}`, "medium"},
		{"connectors-required", `"connectorEnforcement":"REQUIRED","ipConfiguration":{"authorizedNetworks":[{"value":"0.0.0.0/0"}]}`, ""},
		{"narrow", `"ipConfiguration":{"authorizedNetworks":[{"value":"192.0.2.0/24"}]}`, ""},
		{"malformed", `"ipConfiguration":{"authorizedNetworks":[{"value":"invalid"}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := publicSQL(asset("sqladmin.googleapis.com/Instance", `{"settings":{`+tc.settings+`}}`), now)
			if tc.severity == "" {
				if len(got) != 0 {
					t.Fatal(got)
				}
				return
			}
			if len(got) != 1 || got[0].Severity != tc.severity || got[0].Evidence["assessment"] == nil {
				t.Fatal(got)
			}
		})
	}
}
