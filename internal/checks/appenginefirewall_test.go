package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestAppEngineFirewallFirstMatchFamilies(t *testing.T) {
	rule := func(p int, action, source string) any {
		return inventory.Object{"priority": p, "action": action, "sourceRange": source, "description": "SENTINEL"}
	}
	for _, tc := range []struct {
		name  string
		rules []any
		want  int
		scope string
	}{
		{"default allow", []any{rule(2147483647, "ALLOW", "*")}, 2, "all_sources_in_family"},
		{"default deny", []any{rule(2147483647, "DENY", "*")}, 0, ""},
		{"two allow halves", []any{rule(1, "ALLOW", "0.0.0.0/1"), rule(2, "ALLOW", "128.0.0.0/1"), rule(2147483647, "DENY", "*")}, 1, "all_sources_in_family"},
		{"two IPv6 allow halves", []any{rule(1, "ALLOW", "::/1"), rule(2, "ALLOW", "8000::/1"), rule(2147483647, "DENY", "*")}, 1, "all_sources_in_family"},
		{"short IPv4 alias", []any{rule(1, "ALLOW", "0/0"), rule(2147483647, "DENY", "*")}, 1, "all_sources_in_family"},
		{"deny v4 world shadows default", []any{rule(1, "DENY", "0.0.0.0/0"), rule(2147483647, "ALLOW", "*")}, 1, "all_sources_in_family"},
		{"partial deny then allow", []any{rule(1, "DENY", "10.0.0.0/8"), rule(2, "ALLOW", "0.0.0.0/0"), rule(2147483647, "DENY", "*")}, 1, "unmatched_source_fallback"},
		{"two halves shadow default", []any{rule(1, "DENY", "0.0.0.0/1"), rule(2, "DENY", "128.0.0.0/1"), rule(3, "DENY", "::/0"), rule(2147483647, "ALLOW", "*")}, 0, ""},
		{"earlier allow shadows deny", []any{rule(3, "DENY", "10.0.0.0/8"), rule(2, "ALLOW", "10.0.0.0/8"), rule(2147483647, "DENY", "*"), rule(4, "ALLOW", "0.0.0.0/0")}, 1, "all_sources_in_family"},
		{"wildcard deny shadows allow", []any{rule(2, "ALLOW", "0.0.0.0/0"), rule(1, "DENY", "*"), rule(2147483647, "ALLOW", "*")}, 0, ""},
		{"v6 partial", []any{rule(1, "DENY", "2001:db8::/32"), rule(2, "ALLOW", "::/0"), rule(2147483647, "DENY", "*")}, 1, "unmatched_source_fallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := inventory.NewAsset("firewall", "gcpbuster.googleapis.com/AppEngineFirewall", inventory.Object{"complete": true, "rules": tc.rules})
			got := appEngineFirewall(a, time.Now())
			if len(got) != tc.want {
				t.Fatal(got)
			}
			for _, r := range got {
				if r.Evidence["configured_scope"] != tc.scope {
					t.Fatal(r)
				}
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "SENTINEL") {
				t.Fatal(string(b))
			}
		})
	}
}

func TestAppEngineFirewallUnknownPoliciesNoConclusion(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"complete":false,"rules":[{"priority":2147483647,"action":"ALLOW","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[]}`,
		`{"complete":true,"rules":[{"priority":1,"action":"ALLOW","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[{"priority":2147483647,"action":"ALLOW","sourceRange":"0.0.0.0/0"}]}`,
		`{"complete":true,"rules":[{"priority":2147483647,"action":"UNKNOWN","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[{"priority":"2147483647","action":"ALLOW","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[{"priority":1.5,"action":"ALLOW","sourceRange":"*"},{"priority":2147483647,"action":"ALLOW","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[{"priority":1,"action":"DENY","sourceRange":"SENTINEL"},{"priority":2147483647,"action":"ALLOW","sourceRange":"*"}]}`,
		`{"complete":true,"rules":[{"priority":2147483647,"action":"ALLOW","sourceRange":"*"},{"priority":2147483647,"action":"DENY","sourceRange":"*"}]}`,
	} {
		if got := appEngineFirewall(asset("gcpbuster.googleapis.com/AppEngineFirewall", data), time.Now()); len(got) != 0 {
			t.Fatal(data, got)
		}
	}
}
