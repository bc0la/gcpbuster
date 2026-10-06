package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerApigeeProductsPaginationProjection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/organizations/demo/apiproducts" || r.URL.Query().Get("expand") != "true" {
			t.Fatal(r.URL)
		}
		rows := []any{}
		if calls == 1 {
			for i := 0; i < 100; i++ {
				rows = append(rows, Object{"name": fmt.Sprintf("p%03d", i), "approvalType": "auto", "attributes": []any{Object{"name": "access", "value": "public"}, Object{"name": "secret", "value": "SENTINEL"}}})
			}
		} else {
			if r.URL.Query().Get("startKey") != "p099" {
				t.Fatal(r.URL)
			}
			rows = []any{Object{"name": "p099", "approvalType": "auto", "attributes": []any{Object{"name": "access", "value": "public"}, Object{"name": "secret", "value": "SENTINEL"}}}, Object{"name": "p100", "approvalType": "manual"}}
		}
		b, _ := json.Marshal(Object{"apiProduct": rows})
		return response(200, string(b)), nil
	})
	c.viewerPolicy.permissions["apigee.apiproducts.list"] = true
	out := Snapshot{}
	c.collectViewerApigeeProducts(context.Background(), &out, "organizations/demo", "projects/123")
	if calls != 2 || len(out.Assets) != 101 || hasCoverage(out, "failed") {
		t.Fatal(calls, len(out.Assets), out.Coverage)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SENTINEL") || strings.Contains(string(b), "p099") {
		t.Fatal("raw metadata retained")
	}
}
func TestViewerApigeeProductsPartialAndGuard(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"apiProduct":[{"name":"bad","approvalType":"auto","attributes":[{"name":"access","value":"public"},{"name":"access","value":"private"}]},{"name":"ok","approvalType":"auto","attributes":[{"name":"access","value":"public"}]}]}`), nil
	})
	c.viewerPolicy.permissions["apigee.apiproducts.list"] = true
	out := Snapshot{}
	c.collectViewerApigeeProducts(context.Background(), &out, "organizations/demo", "projects/123")
	if len(out.Assets) != 2 || out.Assets[0].Resource.Data["projection_complete"] != false || out.Assets[1].Resource.Data["projection_complete"] != true {
		t.Fatal(out)
	}
	ep := "https://apigee.googleapis.com/v1/organizations/demo/apiproducts"
	q := url.Values{"fields": {viewerApigeeProductFields}, "count": {"100"}, "expand": {"true"}}
	if _, e := viewerRequestPermissions("GET", ep, q); e != nil {
		t.Fatal(e)
	}
	q.Set("fields", "*")
	if _, e := viewerRequestPermissions("GET", ep, q); e == nil {
		t.Fatal("broad selector allowed")
	}
	c = testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network without permission"); return nil, nil })
	delete(c.viewerPolicy.permissions, "apigee.apiproducts.list")
	out = Snapshot{}
	c.collectViewerApigeeProducts(context.Background(), &out, "organizations/demo", "projects/123")
	if !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
