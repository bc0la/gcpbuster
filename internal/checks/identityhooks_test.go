package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestIdentityBlockingFunctionsConfiguredNotEnforcement(t *testing.T) {
	a := asset("identitytoolkit.googleapis.com/Config", `{"_gcpbusterIdentityHooks":{"complete":true,"hooks":{"beforeCreate":true,"beforeSignIn":true},"forward_credentials":{"idToken":true,"accessToken":false,"refreshToken":true}}}`)
	got := identityBlockingFunctions(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" || len(got[0].Evidence["configured_events"].([]any)) != 2 || len(got[0].Evidence["forwarded_credential_types"].([]any)) != 2 || !strings.Contains(got[0].Evidence["assessment"].(string), "Anonymous and custom") {
		t.Fatal(got)
	}
	for _, raw := range []any{nil, true, inventory.Object{"complete": false, "hooks": inventory.Object{"beforeCreate": true}}, inventory.Object{"complete": true, "hooks": inventory.Object{"beforeCreate": "true"}}, inventory.Object{"complete": true, "hooks": inventory.Object{}}} {
		a.Resource.Data["_gcpbusterIdentityHooks"] = raw
		if got := identityBlockingFunctions(a, time.Now()); len(got) != 0 {
			t.Fatal(raw, got)
		}
	}
	a.Type = "identitytoolkit.googleapis.com/Tenant"
	if len(identityBlockingFunctions(a, time.Now())) != 0 {
		t.Fatal("project-only metadata must not imply tenant-local hook config")
	}
}
