package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func computeExtrasClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Synthetic capabilities isolate collector behavior, not role membership.
	c.viewerPolicy.permissions = map[string]bool{"compute.instanceTemplates.list": true, "compute.machineImages.list": true}
	return c
}

func TestViewerComputeExtrasGlobalRegionalAndMachineMetadata(t *testing.T) {
	templatePages := 0
	c := computeExtrasClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "compute.googleapis.com" {
			t.Fatal(r.URL, r.Method)
		}
		switch r.URL.Path {
		case "/compute/v1/projects/demo/aggregated/instanceTemplates":
			templatePages++
			if r.URL.Query().Get("returnPartialSuccess") != "true" || r.URL.Query().Get("includeAllScopes") != "true" {
				t.Fatal(r.URL)
			}
			if templatePages == 1 {
				return response(200, `{"items":{"global":{"instanceTemplates":[{"name":"global-template","properties":{"metadata":{"items":[{"key":"startup-script","value":"echo template"}]}},"selfLink":"https://www.googleapis.com/compute/v1/projects/demo/global/instanceTemplates/global-template"}]}},"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"items":{"regions/us-central1":{"instanceTemplates":[{"name":"regional-template","properties":{"serviceAccounts":[{"email":"worker@demo.iam.gserviceaccount.com"}]},"selfLink":"https://compute.googleapis.com/compute/v1/projects/123/regions/us-central1/instanceTemplates/regional-template"}]},"regions/us-east1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}}}`), nil
		case "/compute/v1/projects/demo/global/machineImages":
			return response(200, `{"items":[{"name":"machine-image","instanceProperties":{"metadata":{"items":[{"key":"startup-script","value":"echo machine"}]}}}]}`), nil
		default:
			t.Fatal("unexpected endpoint", r.URL)
			return nil, nil
		}
	})
	var s Snapshot
	c.CollectViewerComputeExtras(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || templatePages != 2 {
		t.Fatal(s)
	}
	if s.Assets[1].Name != "//compute.googleapis.com/projects/demo/regions/us-central1/instanceTemplates/regional-template" || s.Assets[1].Resource.Location != "us-central1" {
		t.Fatal(s.Assets[1])
	}
	if len(List(Get(s.Assets[0].Resource.Data, "properties", "metadata", "items"))) != 1 || len(List(Get(s.Assets[2].Resource.Data, "instanceProperties", "metadata", "items"))) != 1 {
		t.Fatal("metadata lost")
	}
}

func TestViewerComputeExtraPartialWarningKeepsLaterPages(t *testing.T) {
	calls := 0
	c := computeExtrasClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"items":{"global":{"instanceTemplates":[{"name":"one","properties":{}}]},"regions/us-east1":{"warning":{"code":"UNREACHABLE","message":"PRIVATE"}}},"nextPageToken":"next"}`), nil
		}
		return response(200, `{"items":{"regions/us-central1":{"instanceTemplates":[{"name":"two","properties":{}}]}}}`), nil
	})
	var s Snapshot
	c.viewerInstanceTemplates(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || calls != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("warning leaked")
	}
}

func TestViewerComputeExtrasMalformedAndForeign(t *testing.T) {
	for _, body := range []string{`{"items":[]}`, `{"items":{"zones/us-central1-a":{"instanceTemplates":[]}}}`, `{"items":{"regions/../bad":{}}}`, `{"items":{"global":{"instanceTemplates":[{"name":"other","selfLink":"https://www.googleapis.com/compute/v1/projects/foreign/global/instanceTemplates/other"}]}}}`, `{"items":{"global":{"instanceTemplates":[{"name":"bad","properties":"invalid"}]}}}`, `{"items":{"global":{"instanceTemplates":[null]}}}`} {
		c := computeExtrasClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerInstanceTemplates(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(body, s)
		}
	}
}

func TestViewerMachineImagesPaginationFailureAndMissingConfig(t *testing.T) {
	calls := 0
	c := computeExtrasClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"items":[{"name":"metadata-missing"}],"nextPageToken":"next"}`), nil
		}
		return response(403, "PRIVATE"), nil
	})
	var s Snapshot
	c.viewerMachineImages(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || calls != 2 || !hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("error leaked")
	}
}

func TestViewerComputeExtrasPermissionAndScopeGuard(t *testing.T) {
	c := computeExtrasClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network called"); return nil, nil })
	var s Snapshot
	c.CollectViewerComputeExtras(context.Background(), &s, "../bad", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerComputeExtras(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
		t.Fatal(s)
	}
}
