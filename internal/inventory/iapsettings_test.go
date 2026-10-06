package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestIAPSettingsReadTargetsAndPartialFailures(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "iap.googleapis.com" || !strings.HasSuffix(r.URL.Path, ":iapSettings") || strings.Contains(r.URL.Path, "iap_tunnel") {
			t.Fatal(r.URL)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/"), ":iapSettings")
		calls[name]++
		if name == "folders/9" {
			return response(403, "PRIVATE_ERROR"), nil
		}
		b, _ := json.Marshal(Object{"name": name, "accessSettings": Object{"corsSettings": Object{"allowHttpOptions": true}}})
		return response(200, string(b)), nil
	})
	a := NewAsset("//compute.googleapis.com/projects/my-project/global/backendServices/backend", "compute.googleapis.com/BackendService", nil)
	a.Ancestors = []string{"projects/123", "folders/9", "organizations/1"}
	s := Snapshot{Assets: []Asset{a, a, NewAsset("missing", "run.googleapis.com/Service", nil)}}
	c.CollectIAPSettings(context.Background(), &s)
	if len(calls) != 6 || len(s.Assets) != 8 || !hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(calls, s)
	}
	for _, n := range calls {
		if n != 1 {
			t.Fatal("duplicate read")
		}
	}
	for _, a := range s.Assets[3:] {
		if a.Type != "iap.googleapis.com/IapSettings" || a.IAM != nil {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE_ERROR") {
		t.Fatal("error body leaked")
	}
}

func TestIAPSettingsValidation(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"name":"projects/123"}`, true},
		{`{"name":"projects/123","accessSettings":{"oauthSettings":{"programmaticClients":["client"]}}}`, true},
		{`null`, false},
		{`{}`, false},
		{`{"name":"projects/999"}`, false},
		{`{"name":"projects/123","accessSettings":[]}`, false},
		{`{"name":"projects/123","accessSettings":{"corsSettings":"bad"}}`, false},
		{`{"name":"projects/123","accessSettings":{"corsSettings":{"allowHttpOptions":"true"}}}`, false},
		{`{"name":"projects/123","accessSettings":{"oauthSettings":{"programmaticClients":[1]}}}`, false},
	} {
		var d Object
		if err := json.Unmarshal([]byte(tc.body), &d); err != nil {
			t.Fatal(err)
		}
		if valid := validateIAPSettings(d, "projects/123") == nil; valid != tc.valid {
			t.Fatal(tc)
		}
	}
}
