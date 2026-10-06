package inventory

import (
	"net/url"
	"testing"
)

func TestViewerRegionalSecretMetadataGuard(t *testing.T) {
	base := "https://secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets"
	for suffix, permission := range map[string]string{"": "secretmanager.secrets.list", "/secret/versions": "secretmanager.versions.list"} {
		p, err := viewerRequestPermissions("GET", base+suffix, nil)
		if err != nil || len(p) != 1 || p[0] != permission {
			t.Fatal(p, err)
		}
	}
	for _, endpoint := range []string{
		base + "/secret/versions/1:access", base + "/secret:addVersion", base + "/secret/versions/1:disable",
		"https://secretmanager.us-east1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets",
		"https://secretmanager.us-central1.rep.googleapis.com.attacker.invalid/v1/projects/123/locations/us-central1/secrets",
		"https://secretmanager.googleapis.com/v1/projects/123/locations/us-central1/secrets",
		"https://secretmanager.global.rep.googleapis.com/v1/projects/123/locations/global/secrets",
	} {
		if _, err := viewerRequestPermissions("GET", endpoint, nil); err == nil {
			t.Fatal("unreviewed regional request allowed", endpoint)
		}
	}
	if _, err := viewerRequestPermissions("POST", base, nil); err == nil {
		t.Fatal("mutation permitted")
	}
}

func TestViewerTaskAndVertexGuardBoundaries(t *testing.T) {
	tasks := "https://cloudtasks.googleapis.com/v2/projects/123/locations/us-central1/queues/q/tasks"
	for _, query := range []url.Values{nil, {"responseView": {"FULL"}}, {"responseView": {"BASIC", "FULL"}}, {"responseView": {"BASIC"}, "response_view": {"FULL"}}} {
		if _, err := viewerRequestPermissions("GET", tasks, query); err == nil {
			t.Fatal("accepted ambiguous or non-BASIC task view", query)
		}
	}
	if p, err := viewerRequestPermissions("GET", tasks, url.Values{"responseView": {"BASIC"}}); err != nil || len(p) != 1 || p[0] != "cloudtasks.tasks.list" {
		t.Fatal(p, err)
	}
	for _, endpoint := range []string{
		"https://us-east1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/customJobs",
		"https://us-central1-aiplatform.googleapis.com.attacker.test/v1/projects/123/locations/us-central1/customJobs",
		"https://us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/customJobs/1:cancel",
		"https://us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/endpoints/1:predict",
	} {
		if _, err := viewerRequestPermissions("GET", endpoint, nil); err == nil {
			t.Fatal("accepted unmatched regional operation", endpoint)
		}
	}
	endpoint := "https://us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/pipelineJobs/1"
	if p, err := viewerRequestPermissions("GET", endpoint, nil); err != nil || len(p) != 1 || p[0] != "aiplatform.pipelineJobs.get" {
		t.Fatal(p, err)
	}
	if _, err := viewerRequestPermissions("POST", endpoint, nil); err == nil {
		t.Fatal("regional metadata enabled mutation")
	}
}
