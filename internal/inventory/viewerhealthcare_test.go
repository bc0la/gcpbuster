package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerHealthcareDocumentedIdentifierAlphabet(t *testing.T) {
	for _, id := range []string{"data.set", "_private", "-old", "医疗"} {
		parent := "projects/demo/locations/us-central1/datasets/" + id
		name := parent + "/fhirStores/" + id
		if got, ok := canonicalHealthcareName(name, "demo", "projects/123", "fhirStores"); !ok || got != name {
			t.Fatal(name)
		}
		for _, tc := range []struct {
			path string
			q    url.Values
		}{{parent + "/fhirStores", url.Values{"fields": {"fhirStores(name),nextPageToken"}, "pageSize": {"100"}}}, {name + ":getIamPolicy", url.Values{"fields": {"version,bindings,etag"}, "options.requestedPolicyVersion": {"3"}}}} {
			if _, e := viewerRequestPermissions("GET", "https://healthcare.googleapis.com/v1/"+tc.path, tc.q); e != nil {
				t.Fatal(tc.path, e)
			}
		}
	}
	for _, id := range []string{".", "..", "bad/id", "bad?secret=x"} {
		if _, ok := canonicalHealthcareName("projects/demo/locations/us-central1/datasets/"+id, "demo", "projects/123", "datasets"); ok {
			t.Fatal(id)
		}
	}
}

func TestViewerHealthcareMetadataAndPolicies(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "healthcare.googleapis.com" {
			t.Fatal(r.URL)
		}
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			if r.URL.Query().Get("options.requestedPolicyVersion") != "3" || r.URL.Query().Get("fields") != viewerHealthcarePolicyFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/healthcare.fhirResourceReader","members":["allAuthenticatedUsers"]}],"unexpected":"PRIVATE_RECORD"}`), nil
		}
		if r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/demo/locations":
			return response(200, `{"locations":[false,{"name":"projects/123/locations/us-central1","locationId":"us-central1","labels":{"secret":"PRIVATE_RECORD"}}]}`), nil
		case "/v1/projects/demo/locations/us-central1/datasets":
			if r.URL.Query().Get("pageToken") == "next" {
				return response(403, `{"error":{"message":"denied"}}`), nil
			}
			return response(200, `{"datasets":[{"name":"projects/123/locations/us-central1/datasets/data","description":"PRIVATE_RECORD"}],"nextPageToken":"next"}`), nil
		case "/v1/projects/demo/locations/us-central1/datasets/data/fhirStores":
			return response(200, `{"fhirStores":[{"name":"projects/foreign/locations/us-central1/datasets/data/fhirStores/wrong"},{"name":"projects/demo/locations/us-central1/datasets/data/fhirStores/store","unexpected":"PRIVATE_RECORD"}]}`), nil
		case "/v1/projects/demo/locations/us-central1/datasets/data/dicomStores", "/v1/projects/demo/locations/us-central1/datasets/data/hl7V2Stores":
			return response(200, `{}`), nil
		default:
			t.Fatal("unexpected endpoint", r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = map[string]bool{"healthcare.locations.list": true, "healthcare.datasets.list": true, "healthcare.datasets.getIamPolicy": true, "healthcare.fhirStores.list": true, "healthcare.fhirStores.getIamPolicy": true, "healthcare.dicomStores.list": true, "healthcare.hl7V2Stores.list": true}
	out := Snapshot{}
	c.CollectViewerHealthcare(context.Background(), &out, "demo", "projects/123")
	if calls != 8 || len(out.Assets) != 2 || !hasCoverage(out, "failed") || len(List(out.Assets[1].IAM["bindings"])) != 1 {
		t.Fatal(out, calls)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE_RECORD") {
		t.Fatal(string(b))
	}
}

func TestViewerHealthcarePermissionAndScope(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("blocked request reached transport")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{}
	out := Snapshot{}
	c.CollectViewerHealthcare(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") || len(out.Assets) != 0 {
		t.Fatal(out)
	}
	for _, raw := range []string{"projects/foreign/locations/us-central1/datasets/data/fhirStores/store", "projects/demo/locations/us-central1/datasets/data/fhirStores/store/fhir/Patient/1", "projects/demo/locations/us-central1/datasets/data/fhirStores/../foreign"} {
		if _, ok := canonicalHealthcareName(raw, "demo", "projects/123", "fhirStores"); ok {
			t.Fatal(raw)
		}
	}
	c.viewerPolicy.permissions = map[string]bool{"healthcare.fhirResources.get": true, "healthcare.fhirStores.export": true}
	for _, endpoint := range []string{"https://healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/fhirStores/store/fhir/Patient/1", "https://healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/fhirStores/store:export"} {
		if _, err := c.get(context.Background(), endpoint, nil); err == nil {
			t.Fatal(endpoint)
		}
	}
}
