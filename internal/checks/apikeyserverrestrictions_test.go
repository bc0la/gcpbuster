package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyServerWorldRangesExplicitFamily(t *testing.T) {
	for _, tc := range []struct {
		ips      []any
		families int
	}{
		{[]any{"0.0.0.0/0"}, 1}, {[]any{"::/0"}, 1}, {[]any{"0.0.0.0/0", "::/0"}, 2},
		{[]any{"192.0.2.10", "0.0.0.0/0", "192.0.2.0/24"}, 1},
		{[]any{"192.0.2.0/24", "2001:db8::/64"}, 0}, {[]any{"192.0.2.10"}, 0},
		{[]any{"0.0.0.0/0", "SENTINEL"}, 0}, {[]any{"0.0.0.0/0", false}, 0},
		{[]any{}, 0}, {nil, 0}, {[]any{"::ffff:0.0.0.0/0"}, 0},
	} {
		a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"restrictions": inventory.Object{"apiTargets": []any{inventory.Object{"service": "translate.googleapis.com"}}, "serverKeyRestrictions": inventory.Object{"allowedIps": tc.ips}}})
		got := apiKeys(a, time.Time{})
		if tc.families == 0 {
			if len(got) != 0 {
				t.Fatal(tc, got)
			}
			continue
		}
		if len(got) != 1 || len(arr(got[0].Evidence["unrestricted_ip_families"])) != tc.families {
			t.Fatal(tc, got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), "192.0.2") {
			t.Fatal("raw client IP disclosure")
		}
	}
}

func TestAPIKeyServerRestrictionMissingMalformedUnion(t *testing.T) {
	for _, restrictions := range []any{nil, false, inventory.Object{}, inventory.Object{"serverKeyRestrictions": true}, inventory.Object{"serverKeyRestrictions": inventory.Object{}}, inventory.Object{"serverKeyRestrictions": inventory.Object{"allowedIps": "0.0.0.0/0"}}, inventory.Object{"serverKeyRestrictions": inventory.Object{"allowedIps": []any{"0.0.0.0/0"}}, "browserKeyRestrictions": inventory.Object{}}} {
		a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"restrictions": restrictions})
		if len(apiKeyUnrestrictedServerSources(a)) != 0 {
			t.Fatal(restrictions)
		}
	}
	a := inventory.NewAsset("key", "apikeys.googleapis.com/Key", inventory.Object{"deleteTime": "2026-01-01T00:00:00Z", "restrictions": inventory.Object{"serverKeyRestrictions": inventory.Object{"allowedIps": []any{"0.0.0.0/0"}}}})
	if len(apiKeyUnrestrictedServerSources(a)) != 0 {
		t.Fatal("deleted key")
	}
}
