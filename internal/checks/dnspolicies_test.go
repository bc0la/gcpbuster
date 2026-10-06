package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func dnsTestNetworks() []any {
	return []any{inventory.Object{"networkUrl": "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default", "description": "SENTINEL"}}
}
func TestDNSPolicyForwardingExplicitBoundConfiguration(t *testing.T) {
	a := inventory.NewAsset("policy", "dns.googleapis.com/Policy", inventory.Object{"networks": dnsTestNetworks(), "enableInboundForwarding": true, "description": "SENTINEL", "alternativeNameServerConfig": inventory.Object{"targetNameServers": []any{inventory.Object{"ipv4Address": "10.1.2.3", "forwardingPath": "private", "description": "SENTINEL"}, inventory.Object{"ipv6Address": "2001:db8::1"}}}})
	got := dnsPolicyForwarding(a, time.Now())
	if len(got) != 2 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENTINEL") {
		t.Fatal(string(b))
	}
	for _, v := range []any{nil, []any{}, []any{inventory.Object{"networkUrl": "https://attacker.test/SENTINEL"}}} {
		a.Resource.Data["networks"] = v
		if got := dnsPolicyForwarding(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
func TestDNSZoneResolutionPrivateScopeAndTargetKinds(t *testing.T) {
	for _, target := range []inventory.Object{{"ipv4Address": "192.0.2.53"}, {"ipv6Address": "2001:db8::53", "forwardingPath": "private"}, {"domainName": "resolver.example.test."}} {
		a := inventory.NewAsset("zone", "dns.googleapis.com/ManagedZone", inventory.Object{"visibility": "private", "privateVisibilityConfig": inventory.Object{"networks": dnsTestNetworks()}, "forwardingConfig": inventory.Object{"targetNameServers": []any{target}}})
		if got := dnsZoneResolution(a, time.Now()); len(got) != 1 {
			t.Fatal(target, got)
		}
		a.Resource.Data["visibility"] = "public"
		if got := dnsZoneResolution(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
	a := inventory.NewAsset("zone", "dns.googleapis.com/ManagedZone", inventory.Object{"visibility": "private", "privateVisibilityConfig": inventory.Object{"networks": dnsTestNetworks()}, "peeringConfig": inventory.Object{"targetNetwork": inventory.Object{"networkUrl": "projects/other/global/networks/producer", "description": "SENTINEL"}}})
	got := dnsZoneResolution(a, time.Now())
	if len(got) != 1 || got[0].Evidence["target_network"] != "projects/other/global/networks/producer" {
		t.Fatal(got)
	}
	a.Resource.Data["forwardingConfig"] = inventory.Object{}
	if got := dnsZoneResolution(a, time.Now()); len(got) != 0 {
		t.Fatal("contradictory zone", got)
	}
}
func TestDNSForwardTargetsRejectMalformed(t *testing.T) {
	for _, target := range []inventory.Object{{}, {"ipv4Address": "SENTINEL"}, {"ipv6Address": "1.2.3.4"}, {"ipv4Address": "1.2.3.4", "ipv6Address": "2001:db8::1"}, {"domainName": "https://example.test/path"}, {"ipv4Address": "1.2.3.4", "forwardingPath": "PRIVATE"}, {"ipv4Address": "1.2.3.4", "forwardingPath": false}, {"ipv6Address": "fe80::1%eth0"}} {
		if got := dnsForwardTargets([]any{target}, true); len(got) != 0 {
			t.Fatal(target, got)
		}
	}
	if got := dnsForwardTargets([]any{inventory.Object{"domainName": "resolver.example.test"}}, false); len(got) != 0 {
		t.Fatal(got)
	}
}
func TestDNSQueryLoggingApplicability(t *testing.T) {
	for _, tc := range []struct {
		kind, visibility string
		flag             any
		bound            bool
		want             int
	}{
		{"Policy", "", false, true, 1}, {"Policy", "", false, false, 0}, {"Policy", "", nil, true, 0}, {"Policy", "", "false", true, 0}, {"Policy", "", true, true, 0},
		{"ManagedZone", "public", false, false, 1}, {"ManagedZone", "private", false, true, 0}, {"ManagedZone", "", false, true, 0}, {"ManagedZone", "public", nil, true, 0}, {"ManagedZone", "public", "false", true, 0},
	} {
		d := inventory.Object{"visibility": tc.visibility, "enableLogging": tc.flag, "cloudLoggingConfig": inventory.Object{"enableLogging": tc.flag}}
		if tc.bound {
			d["networks"] = dnsTestNetworks()
		}
		a := inventory.NewAsset("dns", "dns.googleapis.com/"+tc.kind, d)
		if got := dnsQueryLogging(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
