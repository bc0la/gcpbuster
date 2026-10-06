package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerDataflowAggregatedDetailAndPartialPages(t *testing.T) {
	pages := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		if strings.HasSuffix(r.URL.Path, "jobs:aggregated") {
			pages++
			if r.URL.Query().Get("filter") != "ALL" {
				t.Fatal(r.URL)
			}
			if pages == 1 {
				return response(200, `{"jobs":[],"failedLocation":[{"name":"us-east1"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"jobs":[{"id":"job1","projectId":"demo","location":"europe-west1"}]}`), nil
		}
		if r.URL.Path != "/v1b3/projects/demo/locations/europe-west1/jobs/job1" || r.URL.Query().Get("view") != "JOB_VIEW_ALL" || r.URL.Query().Get("fields") != viewerDataflowFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"id":"job1","projectId":"demo","location":"europe-west1","environment":{"sdkPipelineOptions":{"password":"CONFIG_SECRET"}},"executionInfo":{"payload":"DO_NOT_KEEP_OUTPUT"}}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"dataflow.jobs.list": true, "dataflow.jobs.get": true}
	var s Snapshot
	c.CollectViewerDataflow(context.Background(), &s, "demo", "projects/123")
	if pages != 2 || len(s.Assets) != 1 || !hasCoverage(s, "failed") || s.Assets[0].Name != "//dataflow.googleapis.com/projects/demo/locations/europe-west1/jobs/job1" {
		t.Fatal(s, pages)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP_OUTPUT") || Str(Get(s.Assets[0].Resource.Data, "environment", "sdkPipelineOptions", "password")) != "CONFIG_SECRET" {
		t.Fatal("projection failed")
	}
}

func TestViewerDataflowRejectsForeignAndMissingDetail(t *testing.T) {
	for _, body := range []string{`{"id":"job2","projectId":"demo","location":"us-central1"}`, `{"id":"job1","projectId":"foreign","location":"us-central1"}`, `null`} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "jobs:aggregated") {
				return response(200, `{"jobs":[{"id":"job1","projectId":"demo","location":"us-central1"}]}`), nil
			}
			return response(200, body), nil
		})
		var s Snapshot
		c.CollectViewerDataflow(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("request without permissions"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	var s Snapshot
	c.CollectViewerDataflow(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerDataflowMissingEnvironmentAndExternalStepsIncomplete(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		row := `{"id":"job1","projectId":"demo","location":"us-central1","stepsLocation":"gs://bucket/steps"}`
		if strings.HasSuffix(r.URL.Path, "jobs:aggregated") {
			return response(200, `{"jobs":[`+row+`]}`), nil
		}
		return response(200, row), nil
	})
	var s Snapshot
	c.CollectViewerDataflow(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "incomplete") {
		t.Fatal(s)
	}
}
