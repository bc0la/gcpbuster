package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDataprocWorkloadTransientApprovedFields(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" {
			t.Fatal("mutation")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			if r.URL.Query().Get("fields") != dataprocJobSecretFields {
				t.Fatal("mask")
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"jobs":[{"reference":{"projectId":"demo","jobId":"j1"},"pysparkJob":{"args":["--password=ARGS_SENTINEL"],"properties":{"token":"PROPERTY_SENTINEL"}},"hiveJob":{"queryList":{"queries":["select 'QUERY_SENTINEL'"]},"scriptVariables":{"password":"VARIABLE_SENTINEL"}}}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{}`), nil
		case strings.HasSuffix(r.URL.Path, "/batches"):
			if r.URL.Query().Get("fields") != dataprocBatchSecretFields {
				t.Fatal("mask")
			}
			return response(200, `{"batches":[{"name":"projects/123/locations/us-central1/batches/b1","runtimeConfig":{"properties":{"password":"BATCH_SENTINEL"}},"sparkBatch":{"args":["ARG_SENTINEL"]},"sparkSqlBatch":{"queryVariables":{"token":"SQL_SENTINEL"}}}]}`), nil
		case strings.HasSuffix(r.URL.Path, "/workflowTemplates"):
			if r.URL.Query().Get("fields") != dataprocTemplateSecretFields {
				t.Fatal("mask")
			}
			return response(200, `{"templates":[{"name":"projects/demo/regions/us-central1/workflowTemplates/t1","jobs":[{"stepId":"step1","sparkJob":{"args":["TEMPLATE_SENTINEL"],"properties":{"token":"TEMPLATE_PROPERTY_SENTINEL"}}}],"placement":{"managedCluster":{"config":{"gceClusterConfig":{"metadata":{"password":"META_SENTINEL"}},"softwareConfig":{"properties":{"password":"SOFTWARE_SENTINEL"}}}}}}]}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	for _, permission := range []string{"dataproc.jobs.list", "dataproc.batches.list", "dataproc.workflowTemplates.list"} {
		c.viewerPolicy.permissions[permission] = true
	}
	c.SecretCapture = NewSecretCapture(50, 4096, 65536)
	s := Snapshot{}
	c.viewerDataprocWorkloads(context.Background(), &s, "demo", "projects/123", "us-central1")
	if calls != 4 || len(c.SecretCapture.Samples()) != 11 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(calls, len(c.SecretCapture.Samples()), s.Coverage)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "SENTINEL") || len(s.Assets) != 0 {
		t.Fatal("snapshot leak")
	}
}

func TestDataprocWorkloadGuardAndUnreachable(t *testing.T) {
	for _, kind := range []string{"jobs", "batches", "workflowTemplates"} {
		scope, fields := "regions", dataprocJobSecretFields
		if kind == "batches" {
			scope = "locations"
			fields = dataprocBatchSecretFields
		}
		if kind == "workflowTemplates" {
			fields = dataprocTemplateSecretFields
		}
		u, _ := url.Parse("https://dataproc.googleapis.com/v1/projects/demo/" + scope + "/us-central1/" + kind)
		q := url.Values{"pageSize": {"100"}, "fields": {fields}}
		if _, e := dataprocSecretPermissions("GET", u, q); e != nil {
			t.Fatal(e)
		}
		q.Set("fields", "*")
		if _, e := dataprocSecretPermissions("GET", u, q); e == nil {
			t.Fatal("wildcard accepted")
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"unreachable":["sensitive-names-not-in-error"]}`), nil
	})
	for _, p := range []string{"dataproc.jobs.list", "dataproc.batches.list", "dataproc.workflowTemplates.list"} {
		c.viewerPolicy.permissions[p] = true
	}
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	s := Snapshot{}
	c.viewerDataprocWorkloads(context.Background(), &s, "demo", "projects/123", "us-central1")
	if !hasCoverage(s, "incomplete") && !hasCoverage(s, "failed") {
		t.Fatal(s.Coverage)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "sensitive-names") {
		t.Fatal("unreachable leaked")
	}
}

func TestDataprocWorkloadForeignResourcesNeverCaptured(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			return response(200, `{"jobs":[{"reference":{"projectId":"foreign","jobId":"j1"},"sparkJob":{"args":["FOREIGN_SENTINEL"]}}]}`), nil
		case strings.HasSuffix(r.URL.Path, "/batches"):
			return response(200, `{"batches":[{"name":"projects/foreign/locations/us-central1/batches/b1","runtimeConfig":{"properties":{"password":"FOREIGN_SENTINEL"}}}]}`), nil
		default:
			return response(200, `{"templates":[{"name":"projects/demo/regions/foreign/workflowTemplates/t1","jobs":[{"sparkJob":{"args":["FOREIGN_SENTINEL"]}}]}]}`), nil
		}
	})
	for _, p := range []string{"dataproc.jobs.list", "dataproc.batches.list", "dataproc.workflowTemplates.list"} {
		c.viewerPolicy.permissions[p] = true
	}
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	s := Snapshot{}
	c.viewerDataprocWorkloads(context.Background(), &s, "demo", "projects/123", "us-central1")
	if len(c.SecretCapture.Samples()) != 0 || len(s.Coverage) != 3 || !hasCoverage(s, "failed") && !hasCoverage(s, "incomplete") {
		t.Fatal(s.Coverage, c.SecretCapture.Samples())
	}
}
