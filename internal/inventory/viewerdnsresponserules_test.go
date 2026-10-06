package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func responseRulePolicy() Asset {
	return NewAsset("//dns.googleapis.com/projects/demo/responsePolicies/12", "dns.googleapis.com/ResponsePolicy", Object{"id": "12", "responsePolicyName": "policy", "networks": []any{Object{"networkUrl": "projects/demo/global/networks/default"}}})
}
func TestViewerDNSResponseRulesPaginationSafeProjection(t *testing.T) {
	pages := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "dns.googleapis.com" || r.URL.Path != "/dns/v1/projects/demo/responsePolicies/policy/rules" || r.URL.Query().Get("fields") != viewerDNSResponseRuleFields {
			t.Fatal(r.URL)
		}
		pages++
		if pages == 1 {
			return response(200, `{"responsePolicyRules":[{"ruleName":"local","dnsName":"*.example.test.","description":"SENTINEL","localData":{"localDatas":[{"name":"*.example.test.","type":"TXT","ttl":300,"rrdatas":["\"password=supersecretvalue\""]},{"name":"*.example.test.","type":"A","ttl":300,"rrdatas":["192.0.2.1"]}]}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"responsePolicyRules":[{"ruleName":"bypass","dnsName":"allowed.example.test.","behavior":"bypassResponsePolicy"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"dns.responsePolicyRules.list": true}
	out := Snapshot{Assets: []Asset{responseRulePolicy()}}
	c.CollectViewerDNSResponseRules(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 3 || hasCoverage(out, "failed") || pages != 2 {
		t.Fatal(out)
	}
	if out.Assets[1].Type != DNSResponsePolicyRuleType || Get(out.Assets[1].Resource.Data, "_gcpbusterPolicyBindings", "networks") == nil {
		t.Fatal(out.Assets)
	}
	b, _ := json.Marshal(out)
	for _, s := range []string{"SENTINEL", "supersecretvalue", `"rrdatas":`} {
		if strings.Contains(string(b), s) {
			t.Fatal(string(b))
		}
	}
}
func TestViewerDNSResponseRulesMalformedAndDeniedPartials(t *testing.T) {
	for _, mode := range []string{"malformed", "late", "permission", "server"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if mode == "permission" {
					t.Fatal("permission bypass")
				}
				if mode == "server" || r.URL.Query().Get("pageToken") != "" {
					return response(403, `{}`), nil
				}
				next := ""
				if mode == "late" {
					next = `,"nextPageToken":"late"`
				}
				return response(200, `{"responsePolicyRules":[null,{"ruleName":"../bad","dnsName":"a.test.","behavior":"bypassResponsePolicy"},{"ruleName":"valid","dnsName":"a.test.","behavior":"bypassResponsePolicy"}]`+next+`}`), nil
			})
			c.viewerPolicy.permissions = map[string]bool{"dns.responsePolicyRules.list": mode != "permission"}
			out := Snapshot{Assets: []Asset{responseRulePolicy()}}
			c.CollectViewerDNSResponseRules(context.Background(), &out, "demo", "projects/123")
			want := 2
			if mode == "server" || mode == "permission" {
				want = 1
			}
			if len(out.Assets) != want || !hasCoverage(out, "failed") {
				t.Fatal(out)
			}
		})
	}
}
func TestViewerDNSResponseRulesScopeAndAmbiguousParents(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{"dns.responsePolicyRules.list": true}
	foreign := responseRulePolicy()
	foreign.Name = "//dns.googleapis.com/projects/other/responsePolicies/12"
	conflict := responseRulePolicy()
	conflict.Name = "//dns.googleapis.com/projects/demo/responsePolicies/13"
	conflict.Resource.Data["id"] = "13"
	out := Snapshot{Assets: []Asset{foreign, responseRulePolicy(), conflict}}
	c.CollectViewerDNSResponseRules(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 3 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
func TestViewerDNSResponseRuleUnionAndRecordScope(t *testing.T) {
	for _, data := range []string{`{"ruleName":"r","dnsName":"https://evil/","behavior":"bypassResponsePolicy"}`, `{"ruleName":"r","dnsName":"a.test.","behavior":"unknown"}`, `{"ruleName":"r","dnsName":"a.test.","behavior":"bypassResponsePolicy","localData":{"localDatas":[]}}`, `{"ruleName":"r","dnsName":"a.test."}`} {
		var d Object
		json.Unmarshal([]byte(data), &d)
		if got, e := viewerDNSResponseRuleProjection(d); got != nil || e == nil {
			t.Fatal(data, got, e)
		}
	}
	d := Object{"ruleName": "r", "dnsName": "a.test.", "localData": Object{"localDatas": []any{Object{"name": "foreign.test.", "type": "A", "ttl": float64(1), "rrdatas": []any{"1.2.3.4"}}, Object{"name": "a.test.", "type": "NS", "ttl": float64(1), "rrdatas": []any{"ns.example.test."}}, Object{"name": "a.test.", "type": "A", "ttl": float64(1), "rrdatas": []any{"1.2.3.4"}}}}}
	got, e := viewerDNSResponseRuleProjection(d)
	if got == nil || e == nil || got["complete"] != false || len(List(Get(got, "localData", "localDatas"))) != 1 {
		t.Fatal(got, e)
	}
}
