package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHistoricalConfigurationScopedTransient(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" {
			t.Fatal("mutation")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, ":listRevisions"):
			if r.URL.Query().Get("fields") != workflowRevisionNamesFields {
				t.Fatal("mask")
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"workflows":[{"name":"projects/demo/locations/us-central1/workflows/w","revisionId":"000001-a4d"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{}`), nil
		case strings.HasSuffix(r.URL.Path, "/workflows/w"):
			if r.URL.Query().Get("revisionId") != "000001-a4d" || r.URL.Query().Get("fields") != workflowRevisionConfigFields {
				t.Fatal("revision read")
			}
			return response(200, `{"name":"projects/123/locations/us-central1/workflows/w","revisionId":"000001-a4d","sourceContents":"password=HISTORICAL_SENTINEL","userEnvVars":{"token":"ENV_SENTINEL"}}`), nil
		case strings.HasSuffix(r.URL.Path, "/revisions"):
			if r.URL.Query().Get("showDeleted") != "true" || r.URL.Query().Get("fields") != runRevisionConfigFields {
				t.Fatal("run mask")
			}
			return response(200, `{"revisions":[{"name":"projects/123/locations/us-central1/services/s/revisions/s-00001-a4d","service":"projects/demo/locations/us-central1/services/s","serviceAccount":"REVISION_SENTINEL@example.invalid","containers":[{"image":"IMAGE_SENTINEL.invalid","env":[{"name":"PASSWORD","value":"RUN_SENTINEL"}],"args":["--token=ARG_SENTINEL"]}]}]}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	c.viewerPolicy.permissions["workflows.workflows.listRevision"] = true
	c.viewerPolicy.permissions["run.revisions.list"] = true
	s := Snapshot{Assets: []Asset{NewAsset("//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", "workflows.googleapis.com/Workflow", Object{}), NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/services/s", "run.googleapis.com/Service", Object{})}}
	c.CollectViewerHistoricalSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 0 {
		t.Fatal("nilcapture requested")
	}
	c.SecretCapture = NewSecretCapture(20, 4096, 32768)
	c.CollectViewerHistoricalSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 4 || len(c.SecretCapture.Samples()) != 6 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(calls, s.Coverage, c.SecretCapture.Samples())
	}
	contextValues := map[string]string{}
	for _, sample := range c.SecretCapture.Samples() {
		if sample.SourceType == "run_revision_config" {
			contextValues[sample.Path] = string(sample.Data)
		}
	}
	if contextValues["serviceAccount"] != "serviceAccount=REVISION_SENTINEL@example.invalid" || contextValues["containers[0].image"] != "image=IMAGE_SENTINEL.invalid" {
		t.Fatal("retained revision context missing", contextValues)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal("snapshot leaked")
	}
}

func TestHistoricalConfigurationGuardAndForeignRevision(t *testing.T) {
	detail, _ := url.Parse("https://run.googleapis.com/v2/projects/demo/locations/us-central1/services/s/revisions/s-00001-a4d")
	query := url.Values{"fields": {runRevisionDetailFields}}
	if permissions, err := ViewerRequestPermissions("GET", detail.String(), query); err != nil || len(permissions) != 1 || permissions[0] != "run.revisions.get" {
		t.Fatal(permissions, err)
	}
	query.Set("fields", "*")
	if _, err := ViewerRequestPermissions("GET", detail.String(), query); err == nil {
		t.Fatal("wildcard detail accepted")
	}
	if _, err := ViewerRequestPermissions("POST", detail.String(), url.Values{"fields": {runRevisionDetailFields}}); err == nil {
		t.Fatal("mutation accepted")
	}
	u, _ := url.Parse("https://workflows.googleapis.com/v1/projects/demo/locations/us-central1/workflows/w")
	q := url.Values{"revisionId": {"000001-a4d"}, "fields": {workflowRevisionConfigFields}}
	if _, e := historicalSecretPermissions("GET", u, q); e != nil {
		t.Fatal(e)
	}
	q.Set("revisionId", "../other")
	if _, e := historicalSecretPermissions("GET", u, q); e == nil {
		t.Fatal("invalidrevision accepted")
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"revisions":[{"name":"projects/foreign/locations/us-central1/services/s/revisions/s-00001-a4d","containers":[{"env":[{"name":"PASSWORD","value":"FOREIGN_SENTINEL"}]}]}]}`), nil
	})
	c.viewerPolicy.permissions["run.revisions.list"] = true
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	s := Snapshot{Assets: []Asset{NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/services/s", "run.googleapis.com/Service", Object{})}}
	c.CollectViewerHistoricalSecrets(context.Background(), &s, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) != 0 || !hasCoverage(s, "failed") && !hasCoverage(s, "incomplete") {
		t.Fatal(s.Coverage)
	}
}
