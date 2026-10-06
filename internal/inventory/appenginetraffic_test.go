package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAppEngineTrafficSplitProjection(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{`{"allocations":{"v1":0.9,"v2":0.1},"shardBy":"COOKIE","unknown":"SENTINEL"}`, true},
		{`{"allocations":{"v1":1}}`, true},
		{`{}`, false}, {`null`, false}, {`{"allocations":{}}`, false},
		{`{"allocations":{"v1":0}}`, false}, {`{"allocations":{"v1":0.5}}`, false},
		{`{"allocations":{"v1":"1"}}`, false}, {`{"allocations":{"../v1":1}}`, false},
		{`{"allocations":{"v1":1},"shardBy":"UNKNOWN"}`, false},
	} {
		var input any
		if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
			t.Fatal(err)
		}
		got, valid := projectAppEngineSplit(input)
		if valid != tc.valid || got["unknown"] != nil {
			t.Fatal(tc.input, got, valid)
		}
	}
}

func TestViewerAppEngineTrafficExactChildren(t *testing.T) {
	for _, tc := range []struct {
		split     string
		known     bool
		fraction  float64
		duplicate bool
	}{
		{`{"allocations":{"current":1}}`, true, 0, false},
		{`{"allocations":{"old":0.1,"current":0.9}}`, true, 0.1, false},
		{`{"allocations":{"current":0.4}}`, false, 0, false},
		{`null`, false, 0, false},
		{`{"allocations":{"current":1}}`, false, 0, true},
	} {
		c := appEngineClient(t, func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/v1/apps/demo":
				return response(200, `{"name":"apps/demo"}`), nil
			case "/v1/apps/demo/services":
				extra := ""
				if tc.duplicate {
					extra = `,{"name":"apps/demo/services/default","split":{"allocations":{"old":1}}}`
				}
				return response(200, `{"services":[{"name":"apps/demo/services/default","split":`+tc.split+`}`+extra+`]}`), nil
			case "/v1/apps/demo/services/default/versions":
				return response(200, `{"versions":[{"name":"apps/demo/services/default/versions/old"},{"name":"apps/foreign/services/default/versions/evil"}]}`), nil
			case "/v1/apps/demo/services/default/versions/old":
				return response(200, `{"name":"apps/demo/services/default/versions/old","servingStatus":"SERVING"}`), nil
			default:
				t.Fatal(r.URL)
				return nil, nil
			}
		})
		out := Snapshot{}
		c.CollectViewerAppEngine(context.Background(), &out, "demo", "projects/123")
		if len(out.Assets) != 3 {
			t.Fatal(out)
		}
		marker := Obj(out.Assets[2].Resource.Data["_gcpbusterTrafficAllocation"])
		if (marker != nil) != tc.known {
			t.Fatal(tc, marker)
		}
		if tc.known && (marker["fraction"] != tc.fraction || marker["service"] != "apps/demo/services/default") {
			t.Fatal(tc, marker)
		}
	}
}
