package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestViewerDNSZoneProjection(t *testing.T) {
	d := Object{"id": "1", "name": "internal", "dnsName": "example.test.", "visibility": "private", "description": "SECRET_SENTINEL", "labels": Object{"token": "SECRET_SENTINEL"}, "cloudLoggingConfig": Object{"enableLogging": false}, "forwardingConfig": Object{"targetNameServers": []any{Object{"ipv4Address": "8.8.8.8", "forwardingPath": "default", "description": "SECRET_SENTINEL"}, Object{"ipv6Address": "2001:4860:4860::8888", "forwardingPath": "private"}, Object{"domainName": "resolver.example.test."}}}, "peeringConfig": Object{"targetNetwork": Object{"networkUrl": "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}}, "privateVisibilityConfig": Object{"networks": []any{Object{"networkUrl": "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}}}}
	peer := d["peeringConfig"]
	delete(d, "peeringConfig")
	got, err := projectViewerDNSZone(d)
	if err != nil || len(List(Get(got, "forwardingConfig", "targetNameServers"))) != 3 {
		t.Fatal(got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET_SENTINEL") || strings.Contains(string(b), "description") {
		t.Fatal(string(b))
	}
	d["peeringConfig"] = peer
	if got, err := projectViewerDNSZone(d); err == nil || got["peeringConfig"] != nil || got["forwardingConfig"] != nil {
		t.Fatal(got, err)
	}
	delete(d, "forwardingConfig")
	if got, err := projectViewerDNSZone(d); err != nil || got["peeringConfig"] == nil {
		t.Fatal(got, err)
	}
}

func TestViewerDNSZoneMalformedRouting(t *testing.T) {
	for _, field := range []struct {
		key   string
		value any
	}{
		{"visibility", false}, {"cloudLoggingConfig", Object{"enableLogging": "false"}},
		{"peeringConfig", Object{"targetNetwork": Object{"networkUrl": "https://evil.test/SECRET"}}},
		{"forwardingConfig", Object{"targetNameServers": []any{Object{"ipv4Address": "8.8.8.8", "ipv6Address": "::1"}}}},
		{"forwardingConfig", Object{"targetNameServers": []any{Object{"domainName": "https://evil.test/"}}}},
		{"forwardingConfig", Object{"targetNameServers": []any{Object{"ipv4Address": "not-an-ip"}}}},
		{"forwardingConfig", Object{"targetNameServers": []any{Object{"ipv4Address": "8.8.8.8", "forwardingPath": "PRIVATE"}}}},
		{"privateVisibilityConfig", Object{"networks": []any{Object{"networkUrl": "https://evil.test/"}}}},
	} {
		d := Object{"id": "1", "name": "internal", "dnsName": "example.test.", field.key: field.value}
		got, err := projectViewerDNSZone(d)
		if err == nil || got == nil || got[field.key] != nil {
			t.Fatal(field, got, err)
		}
	}
	for _, domain := range []string{"", "missing-dot", "https://example.test/.", "bad..example.", strings.Repeat("x", 64) + ".test."} {
		if got, err := projectViewerDNSZone(Object{"id": "1", "name": "internal", "dnsName": domain}); got != nil || err == nil {
			t.Fatal(domain, got, err)
		}
	}
}
