package inventory

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestDNSResolutionExplicitPublicAndValidatedNames(t *testing.T) {
	calls := 0
	c := viewerDNSIAMClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return response(200, `{"rrsets":[{"name":"www.example.com.","type":"CNAME","rrdatas":["missing.example.com.","https://secret.example.com/", "192.0.2.1"]},{"name":"https://bad.example.com/","type":"CNAME","rrdatas":["ignored.example.com."]}]}`), nil
	})
	lookups := 0
	c.LookupHost = func(ctx context.Context, name string) ([]string, error) {
		lookups++
		if name != "missing.example.com." {
			t.Fatal(name)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing timeout")
		}
		return nil, fmt.Errorf("wrapped: %w", &net.DNSError{IsNotFound: true})
	}
	var s Snapshot
	for _, v := range []string{"public", "private", ""} {
		s.Assets = append(s.Assets, NewAsset("//dns.googleapis.com/projects/demo/managedZones/11", "dns.googleapis.com/ManagedZone", Object{"name": "external", "visibility": v}))
	}
	c.collectDNS(context.Background(), &s)
	if calls != 1 || lookups != 1 || len(s.Assets) != 4 {
		t.Fatal(calls, lookups, s)
	}
	if s.Assets[3].Resource.Data["targetStatus"] != "address_not_found" {
		t.Fatal(s.Assets[3])
	}
}

func TestDNSResolutionUnknownAndSuccess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		err       error
		want      string
	}{
		{"success", []string{"192.0.2.1"}, nil, "resolved"},
		{"empty", nil, nil, "unknown"},
		{"timeout", nil, &net.DNSError{IsTimeout: true}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := viewerDNSIAMClient(t, func(*http.Request) (*http.Response, error) {
				return response(200, `{"rrsets":[{"name":"www.example.com.","type":"CNAME","rrdatas":["target.example.com."]}]}`), nil
			})
			c.LookupHost = func(context.Context, string) ([]string, error) { return tc.addresses, tc.err }
			s := Snapshot{Assets: []Asset{NewAsset("//dns.googleapis.com/projects/demo/managedZones/11", "dns.googleapis.com/ManagedZone", Object{"name": "external", "visibility": "public"})}}
			c.collectDNS(context.Background(), &s)
			if len(s.Assets) != 2 || s.Assets[1].Resource.Data["targetStatus"] != tc.want {
				t.Fatal(s)
			}
		})
	}
}

func TestDNSLookupNameValidation(t *testing.T) {
	for _, s := range []string{"https://example.com/", "192.0.2.1", "::1", "single", "a..com", "*.example.com", "-bad.example.com", "a.example.com\n"} {
		if _, ok := DNSLookupName(s); ok {
			t.Fatal(s)
		}
	}
	if name, ok := DNSLookupName("Valid.Example.COM."); !ok || name != "valid.example.com" {
		t.Fatal(name, ok)
	}
}
