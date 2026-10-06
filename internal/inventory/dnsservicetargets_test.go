package inventory

import (
	"strings"
	"testing"
)

func dnsServiceTargetSnapshot() Snapshot {
	zone := "//dns.googleapis.com/projects/demo/managedZones/zone"
	return Snapshot{Assets: []Asset{
		NewAsset(zone, "dns.googleapis.com/ManagedZone", Object{"visibility": "public"}),
		NewAsset(zone+"/record-metadata/"+strings.Repeat("a", 64), DNSRecordSetType, Object{"name": "app.example.", "type": "CNAME", "data_count": 1, "zoneVisibility": "public", "managedZone": zone, "_gcpbusterRecordTargets": []any{Object{"kind": "CNAME", "host": "API.EXAMPLE.", "record_index": 0}}}),
		NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/services/app", "run.googleapis.com/Service", Object{"name": "projects/demo/locations/us-central1/services/app", "uri": "https://api.example"}),
	}}
}

func TestDNSObservedServiceNativeAndMalformedDuplicates(t *testing.T) {
	out := dnsServiceTargetSnapshot()
	zone := out.Assets[0].Name
	out.Assets[1] = NewAsset(zone+"/rrsets/app.example./api.example", "dns.googleapis.com/ResourceRecordSet", Object{"name": "app.example.", "type": "CNAME", "zoneVisibility": "public", "target": "api.example", "targetStatus": "address_not_found"})
	CorrelateDNSServiceTargets(&out)
	if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "matched" {
		t.Fatal("native record did not join")
	}
	out.Assets = append(out.Assets, NewAsset(out.Assets[2].Name, out.Assets[2].Type, Object{"name": out.Assets[2].Resource.Data["name"]}))
	CorrelateDNSServiceTargets(&out)
	if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "unknown" {
		t.Fatal("invalid duplicate remained authoritative")
	}
	for _, typ := range []string{"gateway", "application", "foreign", "partial"} {
		out = dnsServiceTargetSnapshot()
		switch typ {
		case "gateway":
			out.Assets[2] = NewAsset("//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/g", "apigateway.googleapis.com/Gateway", Object{"name": "projects/demo/locations/us-central1/gateways/g", "defaultHostname": "api.example"})
		case "application":
			out.Assets[2] = NewAsset("//appengine.googleapis.com/apps/demo", "appengine.googleapis.com/Application", Object{"name": "apps/demo", "defaultHostname": "api.example"})
		case "foreign":
			out.Assets[2] = NewAsset("//appengine.googleapis.com/apps/other", "appengine.googleapis.com/Application", Object{"name": "apps/other", "defaultHostname": "api.example"})
		case "partial":
			out.Assets[1].Resource.Data["data_count"] = 2
		}
		CorrelateDNSServiceTargets(&out)
		want := "matched"
		if typ == "foreign" || typ == "partial" {
			want = "unknown"
		}
		if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != want {
			t.Fatal(typ)
		}
	}
}

func TestDNSObservedServiceExactMatchAndNoNetwork(t *testing.T) {
	out := dnsServiceTargetSnapshot()
	CorrelateDNSServiceTargets(&out)
	marker := Obj(out.Assets[1].Resource.Data["_gcpbusterObservedServiceTarget"])
	if marker["status"] != "matched" || marker["resource"] != out.Assets[2].Name {
		t.Fatal(marker)
	}
	out.Assets = out.Assets[:2]
	CorrelateDNSServiceTargets(&out)
	if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "unknown" {
		t.Fatal("stale match survived")
	}
}

func TestDNSObservedServiceUnknownScopeAndConflicts(t *testing.T) {
	for _, uri := range []string{"https://different.example", "https://api.example.evil", "https://user:pass@api.example", "https://api.example/path", "https://api.example?token=secret"} {
		out := dnsServiceTargetSnapshot()
		out.Assets[2].Resource.Data["uri"] = uri
		CorrelateDNSServiceTargets(&out)
		if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "unknown" {
			t.Fatal(uri)
		}
	}
	out := dnsServiceTargetSnapshot()
	out.Assets[0].Resource.Data["visibility"] = "private"
	CorrelateDNSServiceTargets(&out)
	if out.Assets[1].Resource.Data["_gcpbusterObservedServiceTarget"] != nil {
		t.Fatal("private zone")
	}
	out = dnsServiceTargetSnapshot()
	out.Assets = append(out.Assets, NewAsset("//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway", "apigateway.googleapis.com/Gateway", Object{"name": "projects/demo/locations/us-central1/gateways/gateway", "defaultHostname": "api.example"}))
	CorrelateDNSServiceTargets(&out)
	if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "ambiguous" {
		t.Fatal(out)
	}
	out = dnsServiceTargetSnapshot()
	out.Assets = append(out.Assets, NewAsset(out.Assets[2].Name, out.Assets[2].Type, Object{"name": out.Assets[2].Resource.Data["name"], "uri": "https://different.example"}))
	CorrelateDNSServiceTargets(&out)
	if Get(out.Assets[1].Resource.Data, "_gcpbusterObservedServiceTarget", "status") != "unknown" {
		t.Fatal("conflicting service identity")
	}
}
