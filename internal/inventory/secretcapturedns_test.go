package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDNSRawConfigurationCaptureWithoutSnapshotLeak(t *testing.T) {
	for _, rule := range []bool{false, true} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.Method != "GET" || r.URL.Host != "dns.googleapis.com" {
				t.Fatal(r.URL)
			}
			if rule {
				return response(200, `{"responsePolicyRules":[{"ruleName":"local","dnsName":"text.example.test.","localData":{"localDatas":[{"name":"text.example.test.","type":"TXT","rrdatas":["\"password=RAW_EXAMPLE_VALUE\""],"unreviewed":"DO_NOT_CAPTURE"},{"name":"foreign.example.test.","type":"TXT","rrdatas":["FOREIGN_DENY"]}]}}]}`), nil
			}
			return response(200, `{"rrsets":[{"name":"text.example.test.","type":"TXT","rrdatas":["\"password=RAW_EXAMPLE_VALUE\""],"unreviewed":"DO_NOT_CAPTURE"}]}`), nil
		})
		c.LookupHost = func(context.Context, string) ([]string, error) { t.Fatal("resolver invoked"); return nil, nil }
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		c.viewerPolicy.permissions = map[string]bool{"dns.resourceRecordSets.list": true, "dns.responsePolicyRules.list": true}
		out := Snapshot{}
		if rule {
			out.Assets = []Asset{responseRulePolicy()}
			c.CollectViewerDNSResponseRules(context.Background(), &out, "demo", "projects/123")
		} else {
			out.Assets = []Asset{recordZone("public", "1", "public")}
			c.CollectViewerDNSRecords(context.Background(), &out, "demo", "projects/123")
		}
		ss := c.SecretCapture.Samples()
		if len(ss) != 2 {
			t.Fatal(rule, ss)
		}
		for _, s := range ss {
			if !strings.Contains(string(s.Data), "RAW_EXAMPLE_VALUE") || strings.Contains(string(s.Data), "DO_NOT_CAPTURE") || strings.Contains(string(s.Data), "FOREIGN_DENY") {
				t.Fatal(s)
			}
		}
		b, _ := json.Marshal(out)
		for _, deny := range []string{"RAW_EXAMPLE_VALUE", "DO_NOT_CAPTURE", "FOREIGN_DENY"} {
			if strings.Contains(string(b), deny) {
				t.Fatal("value persisted", rule, deny)
			}
		}
	}
}

func TestDNSRoutingCaptureWhitelistAndBounds(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	c.captureDNSRecord("//dns.googleapis.com/projects/demo/managedZones/1/record-metadata/id", "", Object{"name": "a.example.test.", "type": "A", "routingPolicy": Object{"wrr": Object{"items": []any{Object{"rrdatas": []any{"password=ROUTING_SECRET"}, "unreviewed": "DO_NOT_CAPTURE"}}}, "unknown": Object{"password": "DO_NOT_CAPTURE"}}})
	ss := c.Samples()
	if len(ss) != 1 || ss[0].Path != "routingPolicy.wrr.items[0].rrdatas[0]" || string(ss[0].Data) != "password=ROUTING_SECRET" {
		t.Fatal(ss)
	}
	c = NewSecretCapture(0, 0, 0)
	c.captureDNSRecord("//dns.googleapis.com/projects/demo/managedZones/1/record-metadata/id", "", Object{"rrdatas": []any{strings.Repeat("x", (4<<20)+1)}})
	if len(c.Samples()) != 0 || c.Coverage()[0].Status != "incomplete" {
		t.Fatal("limit not reported")
	}
}
