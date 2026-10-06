package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDataprocSecretsScopedConfigurationOnly(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" {
			t.Fatal("mutation")
		}
		if r.URL.Host == "compute.googleapis.com" {
			return response(200, `{"items":[{"name":"us-central1","selfLink":"https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1"}]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/jobs") || strings.HasSuffix(r.URL.Path, "/batches") || strings.HasSuffix(r.URL.Path, "/workflowTemplates") {
			return response(200, `{}`), nil
		}
		if r.URL.Host != "dataproc.googleapis.com" || r.URL.Path != "/v1/projects/demo/regions/us-central1/clusters" || r.URL.Query().Get("fields") != dataprocClusterSecretFields {
			t.Fatal(r.URL)
		}
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"clusters":[{"projectId":"demo","clusterName":"cluster","config":{"gceClusterConfig":{"metadata":{"password":"METADATA_SENTINEL"}},"softwareConfig":{"properties":{"spark:password":"PROPERTY_SENTINEL"}}}}],"nextPageToken":"next"}`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerDataprocSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 0 {
		t.Fatal("nil capture requested")
	}
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	c.viewerPolicy.permissions["dataproc.clusters.list"] = true
	for _, permission := range []string{"dataproc.jobs.list", "dataproc.batches.list", "dataproc.workflowTemplates.list"} {
		c.viewerPolicy.permissions[permission] = true
	}
	c.CollectViewerDataprocSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 6 || len(c.SecretCapture.Samples()) != 2 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(calls, s.Coverage)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "SENTINEL") || len(s.Assets) != 0 {
		t.Fatal("snapshot content")
	}
}

func TestDataprocSecretGuardAndForeignIdentity(t *testing.T) {
	u, _ := url.Parse("https://dataproc.googleapis.com/v1/projects/demo/regions/us-central1/clusters")
	q := url.Values{"pageSize": {"100"}, "fields": {dataprocClusterSecretFields}}
	if p, e := dataprocSecretPermissions("GET", u, q); e != nil || len(p) != 1 || p[0] != "dataproc.clusters.list" {
		t.Fatal(p, e)
	}
	if _, e := dataprocSecretPermissions("POST", u, q); e == nil {
		t.Fatal("POST accepted")
	}
	q.Set("fields", "*")
	if _, e := dataprocSecretPermissions("GET", u, q); e == nil {
		t.Fatal("wildcard accepted")
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "compute.googleapis.com" {
			return response(200, `{"items":[{"name":"us-central1"}]}`), nil
		}
		return response(200, `{"clusters":[{"projectId":"foreign","clusterName":"cluster","config":{"gceClusterConfig":{"metadata":{"password":"FOREIGN_SENTINEL"}}}}]}`), nil
	})
	c.SecretCapture = NewSecretCapture(10, 4096, 8192)
	c.viewerPolicy.permissions["dataproc.clusters.list"] = true
	s := Snapshot{}
	c.CollectViewerDataprocSecrets(context.Background(), &s, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) != 0 || !hasCoverage(s, "failed") && !hasCoverage(s, "incomplete") {
		t.Fatal(s.Coverage)
	}
}
