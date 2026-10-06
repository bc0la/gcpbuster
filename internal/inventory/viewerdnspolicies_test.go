package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerDNSPoliciesPaginationProjection(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		if r.Method != "GET" || r.URL.Host != "dns.googleapis.com" || r.URL.Query().Get("maxResults") != "100" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/dns/v1/projects/demo/policies":
			if r.URL.Query().Get("fields") != viewerDNSPolicyFields {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"policies":[{"id":"10","name":"forward","enableLogging":false,"enableInboundForwarding":true,"description":"SOURCE_SENTINEL","networks":[{"networkUrl":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}],"alternativeNameServerConfig":{"targetNameServers":[{"ipv4Address":"8.8.8.8"},{"ipv6Address":"2001:db8::1","forwardingPath":"private"}]}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"policies":[{"id":"11","name":"second"}]}`), nil
		case "/dns/v1/projects/demo/responsePolicies":
			if r.URL.Query().Get("fields") != viewerDNSResponsePolicyFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"responsePolicies":[{"id":"12","responsePolicyName":"response","gkeClusters":[{"gkeClusterName":"projects/other/locations/us-central1/clusters/cluster"}],"labels":{"x":"SOURCE_SENTINEL"}}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	var s Snapshot
	c.CollectViewerDNSPolicies(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("free text leak")
	}
	if Get(s.Assets[0].Resource.Data, "alternativeNameServerConfig") == nil {
		t.Fatal(s)
	}
}

func TestViewerDNSPolicyProjectionRejectsAmbiguity(t *testing.T) {
	for _, extra := range []Object{{"enableLogging": "false"}, {"networks": nil}, {"networks": []any{Object{"networkUrl": "https://evil.test/projects/demo/global/networks/n"}}}, {"alternativeNameServerConfig": Object{"targetNameServers": []any{Object{"ipv4Address": "1.2.3.4", "ipv6Address": "::1"}}}}, {"alternativeNameServerConfig": Object{"targetNameServers": []any{Object{"ipv4Address": "SOURCE_SENTINEL"}}}}, {"alternativeNameServerConfig": Object{"targetNameServers": []any{Object{"ipv4Address": "1.2.3.4", "forwardingPath": "bogus"}}}}, {"dns64Config": nil}} {
		d := Object{"id": "1", "name": "policy"}
		for k, v := range extra {
			d[k] = v
		}
		if _, ok := viewerDNSPolicyProjection(d, "Policy"); ok {
			t.Fatal(extra)
		}
	}
}

func TestViewerDNSPoliciesPartialAndRoleGate(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "responsePolicies") {
			return response(403, "SOURCE_SENTINEL"), nil
		}
		if r.URL.Query().Get("pageToken") == "next" {
			return response(200, `{"policies":[{"id":"2","name":"second"}]}`), nil
		}
		return response(200, `{"policies":[{"id":"bad","name":"bad"},{"id":"1","name":"first"}],"nextPageToken":"next"}`), nil
	})
	var s Snapshot
	c.CollectViewerDNSPolicies(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SOURCE_SENTINEL") {
		t.Fatal("error leaked")
	}
	before := calls
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerDNSPolicies(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerDNSPolicyRejectsMalformedSiblingAddress(t *testing.T) {
	for _, value := range []any{nil, false, 42, ""} {
		d := Object{"id": "1", "name": "policy", "alternativeNameServerConfig": Object{"targetNameServers": []any{Object{"ipv4Address": value, "ipv6Address": "2001:db8::53"}}}}
		if _, ok := viewerDNSPolicyProjection(d, "Policy"); ok {
			t.Fatal(value)
		}
	}
}
