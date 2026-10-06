package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestAPIKeyMalformedRestrictionsNotUnrestricted(t *testing.T) {
	for _, raw := range []any{nil, false, "", inventory.Object{"apiTargets": false}, inventory.Object{"apiTargets": []any{false}}, inventory.Object{"apiTargets": []any{inventory.Object{}}}, inventory.Object{"serverKeyRestrictions": false}, inventory.Object{"serverKeyRestrictions": inventory.Object{}, "browserKeyRestrictions": inventory.Object{}}, inventory.Object{"browserKeyRestrictions": inventory.Object{"allowedReferrers": []any{false}}}, inventory.Object{"serverKeyRestrictions": inventory.Object{"allowedIps": "0.0.0.0/0"}}, inventory.Object{"futureClientRestrictions": inventory.Object{}}} {
		a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"restrictions": raw})
		if got := apiKeys(a, time.Time{}); len(got) != 0 {
			t.Fatal(raw, got)
		}
	}
}

func TestAPIKeyEmptyTargetsAndBrowserWildcardsBoundary(t *testing.T) {
	// REST explicitly documents absent/empty apiTargets as all targets. That is
	// independent of browser pattern acceptance; no universal wildcard claim.
	for _, pattern := range []string{"*", "*/*", "https://*.example.com/*"} {
		client := inventory.Object{"allowedReferrers": []any{pattern}}
		a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"restrictions": inventory.Object{"browserKeyRestrictions": client, "apiTargets": []any{inventory.Object{"service": "translate.googleapis.com"}}}})
		if got := apiKeys(a, time.Time{}); len(got) != 0 {
			t.Fatal("unsupported browser inference", pattern, got)
		}
		obj(a.Resource.Data["restrictions"])["apiTargets"] = []any{}
		got := apiKeys(a, time.Time{})
		if len(got) != 1 || got[0].Title != "API key lacks API targets" {
			t.Fatal(got)
		}
	}
	a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"restrictions": inventory.Object{"apiTargets": []any{inventory.Object{"service": "translate.googleapis.com"}}, "browserKeyRestrictions": inventory.Object{"allowedReferrers": []any{}}}})
	if got := apiKeys(a, time.Time{}); len(got) != 0 {
		t.Fatal("empty browser list interpreted universally", got)
	}
	delete(a.Resource.Data, "restrictions")
	if got := apiKeys(a, time.Time{}); len(got) != 1 {
		t.Fatal("documented absence lost", got)
	}
}
