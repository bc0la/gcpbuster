package inventory

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerArtifactDirectPolicyScopedVersionThree(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			if r.URL.Path != "/v1/projects/demo/locations/us/repositories/repo:getIamPolicy" || r.URL.Query().Get("options.requestedPolicyVersion") != "3" || r.URL.Query().Get("fields") != "version,bindings,etag" {
				t.Fatal(r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/artifactregistry.reader","members":["allUsers"],"condition":{"expression":"false"}}]}`), nil
		}
		return response(200, `{"repositories":[{"name":"projects/123/locations/us/repositories/repo"}]}`), nil
	})
	s := Snapshot{}
	c.viewerAutomationRows(context.Background(), &s, "https://artifactregistry.googleapis.com/v1/projects/demo/locations/us/repositories", "artifactregistry.googleapis.com", "repositories", "Repository", "demo", "projects/123", "us")
	if calls != 2 || len(s.Assets) != 1 || len(List(s.Assets[0].IAM["bindings"])) != 1 || hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	delete(c.viewerPolicy.permissions, "artifactregistry.repositories.getIamPolicy")
	calls = 0
	s = Snapshot{}
	c.viewerAutomationRows(context.Background(), &s, "https://artifactregistry.googleapis.com/v1/projects/demo/locations/us/repositories", "artifactregistry.googleapis.com", "repositories", "Repository", "demo", "projects/123", "us")
	if calls != 1 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	q := url.Values{"fields": {"version,bindings,etag"}, "options.requestedPolicyVersion": {"3"}}
	base := "https://artifactregistry.googleapis.com/v1/projects/demo/locations/us/repositories/repo"
	for _, suffix := range []string{":setIamPolicy", ":download", "/files/file:download", "/dockerImages/image", "/packages/pkg/versions/v"} {
		if _, err := viewerRequestPermissions("GET", base+suffix, q); err == nil {
			t.Fatal(suffix)
		}
	}
	q.Set("fields", "*")
	if _, err := viewerRequestPermissions("GET", base+":getIamPolicy", q); err == nil {
		t.Fatal("unreviewed fields")
	}
}
