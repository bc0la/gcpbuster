package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCloudDeployGuardSelectedReadOnly(t *testing.T) {
	for _, tc := range []struct{ path, fields, permission string }{
		{"/v1/projects/123/locations", cloudDeployLocationsFields, "clouddeploy.locations.list"},
		{"/v1/projects/123/locations/us-central1/deliveryPipelines", cloudDeployPipelineFields, "clouddeploy.deliveryPipelines.list"},
		{"/v1/projects/123/locations/us-central1/targets", cloudDeployTargetFields, "clouddeploy.targets.list"},
	} {
		u, _ := url.Parse("https://clouddeploy.googleapis.com" + tc.path)
		q := url.Values{"fields": {tc.fields}, "pageSize": {"100"}}
		p, err := cloudDeployPermission("GET", u, q)
		if err != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, err)
		}
		q.Set("fields", "*")
		if _, err := cloudDeployPermission("GET", u, q); err == nil {
			t.Fatal("wildcard allowed")
		}
	}
	for _, path := range []string{"/v1/projects/123/locations/us-central1/deliveryPipelines/p/releases/r/rollouts", "/v1/projects/123/locations/-/targets", "/v1/projects/123/locations/us-central1/targets/t", "/v1/projects/123/locations/us-central1/targets:t"} {
		u, _ := url.Parse("https://clouddeploy.googleapis.com" + path)
		if _, err := cloudDeployPermission("GET", u, url.Values{"fields": {cloudDeployTargetFields}, "pageSize": {"100"}}); err == nil {
			t.Fatal("unreviewed request allowed", path)
		}
	}
}

func TestCloudDeployCaptureSelectedParamsOnly(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	a := NewAsset("//clouddeploy.googleapis.com/projects/123/locations/us-central1/deliveryPipelines/p", "clouddeploy.googleapis.com/DeliveryPipeline", Object{"serialPipeline": Object{"stages": []any{Object{"deployParameters": []any{Object{"values": Object{"password": "PIPELINE_VALUE"}, "matchTargetLabels": Object{"password": "DO_NOT_CAPTURE"}}}}}}, "renderedManifest": "DO_NOT_CAPTURE"})
	c.captureCloudDeploy(a)
	a.Type = "clouddeploy.googleapis.com/Target"
	a.Name = "//clouddeploy.googleapis.com/projects/123/locations/us-central1/targets/t"
	a.Resource.Data = Object{"deployParameters": Object{"password": "TARGET_VALUE"}, "artifactStorage": "DO_NOT_CAPTURE"}
	c.captureCloudDeploy(a)
	ss := c.Samples()
	if len(ss) != 2 {
		t.Fatal(ss)
	}
	var b strings.Builder
	for _, s := range ss {
		b.Write(s.Data)
	}
	if !strings.Contains(b.String(), "password=PIPELINE_VALUE") || !strings.Contains(b.String(), "password=TARGET_VALUE") || strings.Contains(b.String(), "DO_NOT_CAPTURE") {
		t.Fatal(b.String())
	}
}

func TestCloudDeployReleaseSnapshotCapture(t *testing.T) {
	a := NewAsset("//clouddeploy.googleapis.com/projects/123/locations/us-central1/deliveryPipelines/p/releases/r", "clouddeploy.googleapis.com/Release", Object{"deployParameters": Object{"password": "RELEASE_VALUE"}, "deliveryPipelineSnapshot": Object{"serialPipeline": Object{"stages": []any{Object{"deployParameters": []any{Object{"values": Object{"password": "HISTORIC_PIPELINE_VALUE"}}}}}}}, "targetSnapshots": []any{Object{"deployParameters": Object{"password": "HISTORIC_TARGET_VALUE"}}}, "targetArtifacts": Object{"secret": "DO_NOT_CAPTURE"}})
	c := NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	ss := c.Samples()
	if len(ss) != 3 {
		t.Fatal(ss)
	}
	var b strings.Builder
	for _, s := range ss {
		b.Write(s.Data)
	}
	for _, value := range []string{"RELEASE_VALUE", "HISTORIC_PIPELINE_VALUE", "HISTORIC_TARGET_VALUE"} {
		if !strings.Contains(b.String(), value) {
			t.Fatal("missing snapshot", value)
		}
	}
	if strings.Contains(b.String(), "DO_NOT_CAPTURE") {
		t.Fatal("artifact captured")
	}
	u, _ := url.Parse("https://clouddeploy.googleapis.com/v1/projects/123/locations/us-central1/deliveryPipelines/p/releases")
	p, err := cloudDeployPermission("GET", u, url.Values{"fields": {cloudDeployReleaseFields}, "pageSize": {"100"}})
	if err != nil || len(p) != 1 || p[0] != "clouddeploy.releases.list" {
		t.Fatal(p, err)
	}
}

func TestCloudDeployCollectorIdentityAndTransientValues(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "clouddeploy.googleapis.com" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/123/locations":
			return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`), nil
		case "/v1/projects/123/locations/us-central1/deliveryPipelines":
			return response(200, `{"deliveryPipelines":[{"name":"projects/demo/locations/us-central1/deliveryPipelines/p","serialPipeline":{"stages":[{"deployParameters":[{"values":{"password":"PIPELINE_VALUE"}}]}]}}]}`), nil
		case "/v1/projects/123/locations/us-central1/targets":
			return response(200, `{"targets":[{"name":"projects/123/locations/us-central1/targets/t","deployParameters":{"password":"TARGET_VALUE"}}]}`), nil
		case "/v1/projects/123/locations/us-central1/deliveryPipelines/p/releases":
			return response(200, `{}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions = map[string]bool{"clouddeploy.locations.list": true, "clouddeploy.deliveryPipelines.list": true, "clouddeploy.targets.list": true, "clouddeploy.releases.list": true}
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	var s Snapshot
	c.CollectViewerCloudDeploy(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || len(c.SecretCapture.Samples()) != 2 || hasCoverage(s, "failed") {
		t.Fatal(s, c.SecretCapture.Samples())
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "_VALUE") {
		t.Fatal("parameter leaked into snapshot")
	}
}
