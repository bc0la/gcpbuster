package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestDNSDanglingRequiresOptionalLookupEvidence(t *testing.T) {
	// Default metadata collection intentionally does not perform address lookups.
	a := asset(inventory.DNSRecordSetType, `{"type":"CNAME","zoneVisibility":"public","_gcpbusterRecordTargets":[{"hostname":"missing.example.com."}]}`)
	if len(dnsDangling(a, time.Now())) != 0 {
		t.Fatal("metadata alone is not nonresolution")
	}
	a.Type = "dns.googleapis.com/ResourceRecordSet"
	if len(dnsDangling(a, time.Now())) != 0 {
		t.Fatal("legacy type alone is not nonresolution")
	}
}

func TestDNSDanglingAddressStatusAndLegacy(t *testing.T) {
	a := asset("dns.googleapis.com/ResourceRecordSet", `{"type":"CNAME","target":"target.example.com.","targetStatus":"address_not_found","zoneVisibility":"public"}`)
	if len(dnsDangling(a, time.Now())) != 1 {
		t.Fatal("missing candidate")
	}
	a.Resource.Data["zoneVisibility"] = ""
	if len(dnsDangling(a, time.Now())) != 0 {
		t.Fatal("unknown visibility")
	}
	a.Resource.Data["targetStatus"] = "NXDOMAIN"
	if len(dnsDangling(a, time.Now())) != 1 {
		t.Fatal("legacy fixture compatibility")
	}
	a.Resource.Data["zoneVisibility"] = "private"
	if len(dnsDangling(a, time.Now())) != 0 {
		t.Fatal("private candidate")
	}
	a.Resource.Data["zoneVisibility"] = "public"
	a.Resource.Data["target"] = "https://secret.example.com/"
	if len(dnsDangling(a, time.Now())) != 0 {
		t.Fatal("invalid target")
	}
}

func TestDNSSecurityRequiresExplicitPublic(t *testing.T) {
	a := asset("dns.googleapis.com/ManagedZone", `{"dnssecConfig":{"state":"off"}}`)
	for _, v := range []string{"", "private", "unknown"} {
		a.Resource.Data["visibility"] = v
		if len(dnsSecurity(a, time.Now())) != 0 {
			t.Fatal(v)
		}
	}
	a.Resource.Data["visibility"] = "public"
	if len(dnsSecurity(a, time.Now())) != 1 {
		t.Fatal("missing public DNSSEC result")
	}
}
