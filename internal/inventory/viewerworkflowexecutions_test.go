package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestWorkflowExecutionCaptureFullScopedTransient(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "workflowexecutions.googleapis.com" || r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != workflowExecutionFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"executions":[{"name":"projects/demo/locations/us-central1/workflows/flow/executions/e1","argument":"password=EXECUTION_SENTINEL","result":"token=RESULT_SENTINEL","error":{"payload":"ERROR_SENTINEL"}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal("missing pagination")
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{Assets: []Asset{NewAsset("//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/flow", "workflows.googleapis.com/Workflow", Object{})}}
	c.CollectViewerWorkflowExecutions(context.Background(), &s, "demo", "projects/123")
	if calls != 0 {
		t.Fatal("nil capture must not fetch")
	}
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	c.viewerPolicy.permissions["workflows.executions.list"] = true
	c.CollectViewerWorkflowExecutions(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(c.SecretCapture.Samples()) != 3 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(calls, s.Coverage, c.SecretCapture.Samples())
	}
	encoded, _ := json.Marshal(s)
	if strings.Contains(string(encoded), "SENTINEL") {
		t.Fatal("snapshot leaked execution content")
	}
}

func TestWorkflowExecutionForeignIdentityAndPolicy(t *testing.T) {
	u, _ := url.Parse("https://workflowexecutions.googleapis.com/v1/projects/demo/locations/us-central1/workflows/flow/executions")
	q := url.Values{"view": {"FULL"}, "pageSize": {"100"}, "fields": {workflowExecutionFields}}
	p, e := workflowExecutionPermissions("GET", u, q)
	if e != nil || len(p) != 1 || p[0] != "workflows.executions.list" {
		t.Fatal(p, e)
	}
	for _, change := range []string{"method", "fields", "query", "callback"} {
		bad := url.Values{}
		for key, values := range q {
			bad[key] = append([]string(nil), values...)
		}
		endpoint := *u
		method := "GET"
		switch change {
		case "method":
			method = "POST"
		case "fields":
			bad.Set("fields", "*")
		case "query":
			bad.Set("filter", "state=FAILED")
		case "callback":
			endpoint.Path += "/e1/callbacks"
		}
		if _, e := workflowExecutionPermissions(method, &endpoint, bad); e == nil {
			t.Fatal("accepted", change)
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"executions":[{"name":"projects/foreign/locations/us-central1/workflows/flow/executions/e1","argument":"FOREIGN_SENTINEL"}]}`), nil
	})
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	c.viewerPolicy.permissions["workflows.executions.list"] = true
	s := Snapshot{Assets: []Asset{NewAsset("//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/flow", "workflows.googleapis.com/Workflow", Object{})}}
	c.CollectViewerWorkflowExecutions(context.Background(), &s, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) != 0 || !hasCoverage(s, "incomplete") && !hasCoverage(s, "failed") {
		t.Fatal(s.Coverage)
	}
}
