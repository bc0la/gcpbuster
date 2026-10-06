package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func viewerDNSIAMClient(t *testing.T, fn roundTrip) *Client {
	t.Helper()
	t.Setenv("VIEWER_DNS_IAM_TOKEN", "test-token")
	c := &Client{TokenEnv: "VIEWER_DNS_IAM_TOKEN", HTTP: &http.Client{Transport: fn}}
	// Only permissions independently verified in Google's Viewer role table;
	// deliberately exclude privileged CAI export, IAM policy and key downloads.
	c.viewerPolicy.permissions = map[string]bool{
		"dns.managedZones.list": true, "dns.resourceRecordSets.list": true,
		"iam.serviceAccounts.list": true, "iam.serviceAccountKeys.list": true,
	}
	return c
}

const viewerAccountFixture = `{"name":"projects/demo/serviceAccounts/12345","projectId":"demo","email":"worker@demo.iam.gserviceaccount.com","uniqueId":"12345","disabled":false}`

func TestViewerDNSIAMMetadataPaginationAndOptIn(t *testing.T) {
	calls := map[string]int{}
	c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal(r.Method, r.URL)
		}
		switch r.URL.Path {
		case "/dns/v1/projects/demo/managedZones":
			if r.URL.Query().Get("pageToken") == "two" {
				return response(200, `{"managedZones":[{"id":"22","name":"internal","dnsName":"internal.example.","visibility":"private"}]}`), nil
			}
			return response(200, `{"managedZones":[{"id":"11","name":"external","dnsName":"example.com.","visibility":"public","dnssecConfig":{"state":"off"}}],"nextPageToken":"two"}`), nil
		case "/dns/v1/projects/demo/managedZones/external/rrsets":
			// Non-CNAME records deliberately exercise collection without causing
			// real DNS/network lookups in the test environment.
			return response(200, `{"rrsets":[{"name":"example.com.","type":"A","rrdatas":["192.0.2.1"]}]}`), nil
		case "/v1/projects/demo/serviceAccounts":
			if r.URL.Query().Get("pageToken") == "more" {
				return response(200, `{"accounts":[`+viewerAccountFixture+`]}`), nil
			}
			return response(200, `{"accounts":[],"nextPageToken":"more"}`), nil
		case "/v1/projects/demo/serviceAccounts/12345/keys":
			if r.URL.Query().Get("keyTypes") != "USER_MANAGED" {
				t.Fatal(r.URL)
			}
			return response(200, `{"keys":[{"name":"projects/-/serviceAccounts/12345/keys/key-one","keyType":"USER_MANAGED","keyOrigin":"USER_PROVIDED","validAfterTime":"2020-01-01T00:00:00Z","disabled":false,"privateKeyData":"DO_NOT_KEEP_PRIVATE","publicKeyData":"DO_NOT_KEEP_PUBLIC"}]}`), nil
		default:
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		}
	})
	c.DNSChecks = true
	prior := NewAsset("//dns.googleapis.com/projects/old/managedZones/99", "dns.googleapis.com/ManagedZone", Object{"name": "old", "visibility": "public"})
	prior.IAM = Object{"bindings": []any{Object{"role": "roles/viewer"}}}
	s := Snapshot{Assets: []Asset{prior}}
	c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 5 {
		t.Fatalf("%+v", s)
	}
	if s.Assets[1].Name != "//dns.googleapis.com/projects/demo/managedZones/11" || s.Assets[3].Name != "//iam.googleapis.com/projects/demo/serviceAccounts/12345" || s.Assets[4].Name != "//iam.googleapis.com/projects/demo/serviceAccounts/12345/keys/key-one" {
		t.Fatal(s.Assets)
	}
	if len(List(s.Assets[0].IAM["bindings"])) != 1 {
		t.Fatal("existing policy overwritten")
	}
	if calls["/dns/v1/projects/demo/managedZones"] != 2 || calls["/v1/projects/demo/serviceAccounts"] != 2 || calls["/dns/v1/projects/demo/managedZones/external/rrsets"] != 1 {
		t.Fatal(calls)
	}
	for _, a := range s.Assets[1:] {
		if len(a.Ancestors) != 1 || a.Ancestors[0] != "projects/123" {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal("unexpected key material retained")
	}
}

func TestViewerDNSIAMPartialAndDenied(t *testing.T) {
	c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/dns/v1/projects/demo/managedZones":
			return response(403, `PRIVATE_UPSTREAM_BODY`), nil
		case "/v1/projects/demo/serviceAccounts":
			if r.URL.Query().Get("pageToken") == "denied" {
				return response(403, `PRIVATE_UPSTREAM_BODY`), nil
			}
			return response(200, `{"accounts":[`+viewerAccountFixture+`],"nextPageToken":"denied"}`), nil
		case "/v1/projects/demo/serviceAccounts/12345/keys":
			return response(403, `PRIVATE_UPSTREAM_BODY`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || len(s.Coverage) != 3 {
		t.Fatal(s)
	}
	for _, coverage := range s.Coverage {
		if coverage.Status != "failed" || strings.Contains(coverage.Error, "PRIVATE_UPSTREAM_BODY") {
			t.Fatal(coverage)
		}
	}
}

func TestViewerDNSIAMMalformedPagesAndIdentities(t *testing.T) {
	for _, tc := range []struct{ name, zones, accounts string }{
		{"zone array", `{"managedZones":{}}`, `{}`},
		{"zone missing numeric id", `{"managedZones":[{"name":"x","dnsName":"x."}]}`, `{}`},
		{"zone unsafe name", `{"managedZones":[{"id":"1","name":"../other","dnsName":"x."}]}`, `{}`},
		{"account array", `{}`, `{"accounts":{}}`},
		{"foreign project", `{}`, `{"accounts":[{"name":"projects/other/serviceAccounts/12345","projectId":"other","email":"worker@other.iam.gserviceaccount.com","uniqueId":"12345"}]}`},
		{"name mismatch", `{}`, `{"accounts":[{"name":"projects/demo/serviceAccounts/999","projectId":"demo","email":"worker@demo.iam.gserviceaccount.com","uniqueId":"12345"}]}`},
		{"malformed pagination", `{}`, `{"accounts":[],"nextPageToken":123}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/managedZones") {
					return response(200, tc.zones), nil
				}
				if strings.HasSuffix(r.URL.Path, "/serviceAccounts") {
					return response(200, tc.accounts), nil
				}
				t.Fatal("key lookup after malformed account", r.URL)
				return nil, nil
			})
			s := Snapshot{}
			c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
			if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerDNSIAMRepeatedPagesAndInvalidScope(t *testing.T) {
	calls := 0
	c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/managedZones") {
			return response(200, `{"nextPageToken":"loop"}`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerDNSIAM(context.Background(), &s, "../other", "projects/123")
	if calls != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	s = Snapshot{}
	c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
	if calls != 3 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
}

func TestViewerDNSIAMRejectsForeignKeyAndMissingPermission(t *testing.T) {
	for _, missingPermission := range []bool{false, true} {
		c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/managedZones") {
				return response(200, `{}`), nil
			}
			if strings.HasSuffix(r.URL.Path, "/serviceAccounts") {
				return response(200, `{"accounts":[`+viewerAccountFixture+`]}`), nil
			}
			if missingPermission {
				t.Fatal("unauthorized key request sent")
			}
			return response(200, `{"keys":[{"name":"projects/other/serviceAccounts/12345/keys/key-one","keyType":"USER_MANAGED"}]}`), nil
		})
		if missingPermission {
			delete(c.viewerPolicy.permissions, "iam.serviceAccountKeys.list")
		}
		s := Snapshot{}
		c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}

func TestViewerDNSIAMKeyListRejectsUnexpectedPagination(t *testing.T) {
	keyCalls := 0
	c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/managedZones") {
			return response(200, `{}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/serviceAccounts") {
			return response(200, `{"accounts":[`+viewerAccountFixture+`]}`), nil
		}
		keyCalls++
		return response(200, `{"keys":[{"name":"projects/demo/serviceAccounts/12345/keys/key-one","keyType":"USER_MANAGED"}],"nextPageToken":"unexpected"}`), nil
	})
	s := Snapshot{}
	c.CollectViewerDNSIAM(context.Background(), &s, "demo", "projects/123")
	if keyCalls != 1 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, keyCalls)
	}
}
