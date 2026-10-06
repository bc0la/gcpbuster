package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func recordZone(name, id, visibility string) Asset {
	return NewAsset("//dns.googleapis.com/projects/demo/managedZones/"+id, "dns.googleapis.com/ManagedZone", Object{"id": id, "name": name, "dnsName": "example.test.", "visibility": visibility})
}
func TestViewerDNSRecordsBothVisibilitiesNoQueries(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "dns.googleapis.com" || r.URL.Query().Get("fields") != viewerDNSRecordFields || r.URL.Query().Get("maxResults") != "100" {
			t.Fatal(r.URL)
		}
		calls[r.URL.Path]++
		if calls[r.URL.Path] == 1 {
			return response(200, `{"rrsets":[{"name":"www.example.test.","type":"A","ttl":30,"rrdatas":["192.0.2.1"]}],"nextPageToken":"more"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "more" {
			t.Fatal(r.URL)
		}
		return response(200, `{"rrsets":[{"name":"text.example.test.","type":"TXT","ttl":30,"rrdatas":["SOURCE_SENTINEL"]}]}`), nil
	})
	c.LookupHost = func(context.Context, string) ([]string, error) { t.Fatal("DNS lookup invoked"); return nil, nil }
	c.viewerPolicy.permissions = map[string]bool{"dns.resourceRecordSets.list": true}
	s := Snapshot{Assets: []Asset{recordZone("public", "1", "public"), recordZone("private", "2", "private")}}
	c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 6 || hasCoverage(s, "failed") || len(calls) != 2 {
		t.Fatal(s, calls)
	}
	for _, a := range s.Assets[2:] {
		if a.Type != DNSRecordSetType {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("raw value leaked")
	}
}
func TestViewerDNSRecordsPartialScopeAndDenial(t *testing.T) {
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"rrsets":[{"name":"evil.other.test.","type":"A","ttl":30,"rrdatas":["192.0.2.1"]},{"name":"good.example.test.","type":"A","ttl":30,"rrdatas":["192.0.2.2"]}],"nextPageToken":"more"}`), nil
		}
		return response(403, "SOURCE_SENTINEL"), nil
	})
	s := Snapshot{Assets: []Asset{recordZone("public", "1", "public")}}
	c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{}
	before := calls
	s = Snapshot{Assets: []Asset{recordZone("public", "1", "public")}}
	c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
func TestViewerDNSRecordsRejectsZoneScope(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })
	for _, mutation := range []func(*Asset){func(a *Asset) { a.Name = "//dns.googleapis.com/projects/other/managedZones/1" }, func(a *Asset) { a.Resource.Data["name"] = "../evil" }, func(a *Asset) { a.Resource.Data["id"] = "999" }, func(a *Asset) { a.Resource.Data["visibility"] = "unknown" }} {
		a := recordZone("public", "1", "public")
		mutation(&a)
		s := Snapshot{Assets: []Asset{a}}
		c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 1 {
			t.Fatal(s)
		}
	}
}

func TestViewerDNSRecordsPrivateSingleLabelAndRoot(t *testing.T) {
	for _, domain := range []string{"internal.", "."} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			calls++
			return response(200, `{"rrsets":[{"name":"host.internal.","type":"A","ttl":30,"rrdatas":["192.0.2.1"]}]}`), nil
		})
		c.LookupHost = func(context.Context, string) ([]string, error) { t.Fatal("lookup"); return nil, nil }
		a := recordZone("private", "1", "private")
		a.Resource.Data["dnsName"] = domain
		s := Snapshot{Assets: []Asset{a}}
		c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
		if calls != 1 || len(s.Assets) != 2 || hasCoverage(s, "failed") {
			t.Fatal(s, calls)
		}
	}
}

func TestViewerDNSRecordsConflictingZoneAliases(t *testing.T) {
	for _, change := range []func(*Asset){func(a *Asset) { a.Resource.Data["name"] = "other" }, func(a *Asset) {
		a.Resource.Data["id"] = "2"
		a.Name = "//dns.googleapis.com/projects/demo/managedZones/2"
	}, func(a *Asset) { a.Resource.Data["dnsName"] = "other.test." }, func(a *Asset) { a.Resource.Data["visibility"] = "private" }} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("ambiguous zone queried"); return nil, nil })
		a, b := recordZone("zone", "1", "public"), recordZone("zone", "1", "public")
		change(&b)
		s := Snapshot{Assets: []Asset{a, b}}
		c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })
	a, b := recordZone("zone", "1", "public"), recordZone("zone", "1", "public")
	b.Name = "//dns.googleapis.com/projects/demo/managedZones/zone"
	s := Snapshot{Assets: []Asset{a, b}}
	c.CollectViewerDNSRecords(context.Background(), &s, "demo", "projects/123")
	if calls != 1 || hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
}
