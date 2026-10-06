package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestIAPTargets(t *testing.T) {
	for _, tc := range []struct{ typ, name, parent, leaf string }{
		{"compute.googleapis.com/Instance", "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm", "iap_tunnel/zones/us-central1-a", "instances/vm"},
		{"compute.googleapis.com/BackendService", "//compute.googleapis.com/projects/p/global/backendServices/backend", "iap_web/compute", "services/backend"},
		{"compute.googleapis.com/RegionBackendService", "//compute.googleapis.com/projects/p/regions/us-central1/backendServices/backend", "iap_web/compute-us-central1", "services/backend"},
		{"run.googleapis.com/Service", "//run.googleapis.com/projects/p/locations/us-central1/services/app", "iap_web/cloud_run-us-central1", "services/app"},
	} {
		a := NewAsset(tc.name, tc.typ, nil)
		a.Ancestors = []string{"projects/123", "folders/5"}
		got, ok := iapTargets(a)
		want := []string{"projects/123/iap_web", "projects/123/iap_tunnel", "projects/123/" + tc.parent, "projects/123/" + tc.parent + "/" + tc.leaf}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatal(tc, got, ok)
		}
		a.Ancestors = []string{"projects/p"}
		if got, ok := iapTargets(a); ok || len(got) != 0 {
			t.Fatal("guessed project number", got)
		}
		a.Ancestors = []string{"projects/123"}
		a.Name = "https://untrusted.example/steal"
		if got, ok := iapTargets(a); ok || len(got) != 2 {
			t.Fatal("accepted invalid source", got)
		}
	}
}

func TestIAPPolicyReadsSeparateResourcesDeduplicateAndRetainFailures(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Host != "iap.googleapis.com" || !strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			t.Fatal(r.URL, r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"options":{"requestedPolicyVersion":3}}` {
			t.Fatal(string(b))
		}
		calls[r.URL.Path]++
		if strings.Contains(r.URL.Path, "iap_tunnel") {
			return response(403, "PRIVATE_ERROR"), nil
		}
		return response(200, `{"version":3,"bindings":[{"role":"roles/iap.httpsResourceAccessor","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`), nil
	})
	a := NewAsset("//run.googleapis.com/projects/p/locations/us-central1/services/app", "run.googleapis.com/Service", nil)
	a.Ancestors = []string{"projects/123"}
	s := Snapshot{Assets: []Asset{a, a, NewAsset("unresolved", "compute.googleapis.com/Instance", nil)}}
	c.CollectIAPPolicies(context.Background(), &s)
	if len(calls) != 4 || len(s.Assets) != 6 || !hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(calls, s)
	}
	for _, n := range calls {
		if n != 1 {
			t.Fatal("duplicate read")
		}
	}
	for _, a := range s.Assets[3:] {
		if a.Type != "iap.googleapis.com/PolicyResource" || !strings.HasPrefix(a.Name, "//iap.googleapis.com/") || a.IAM["version"] != float64(3) {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE_ERROR") {
		t.Fatal("error body leaked")
	}
}

func TestIAPMalformedPolicyIsFailedCoverage(t *testing.T) {
	for _, body := range []string{`null`, `{"bindings":{}}`, `{"bindings":[{"role":"roles/iap.httpsResourceAccessor","members":["allUsers"],"condition":{"expression":"true"}}]}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		s := Snapshot{Assets: []Asset{NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", nil)}}
		c.CollectIAPPolicies(context.Background(), &s)
		if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}
