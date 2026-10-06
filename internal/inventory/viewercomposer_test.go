package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const composerIndexOne = `{"name":"//composer.googleapis.com/projects/demo/locations/us-central1/environments/env-one","assetType":"composer.googleapis.com/Environment","project":"projects/123","location":"us-central1"}`
const composerConfigOne = `{"name":"projects/demo/locations/us-central1/environments/env-one","config":{"softwareConfig":{"envVariables":{"APP_PASSWORD":"sample"},"airflowConfigOverrides":{"core-dags_are_paused_at_creation":"true"},"imageVersion":"composer-3-airflow-2.10.5"},"nodeConfig":{"serviceAccount":"runtime@demo.iam.gserviceaccount.com"}}}`

func composerClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Synthetic capability fixture; official role membership verified separately.
	c.viewerPolicy.permissions = map[string]bool{"cloudasset.assets.searchAllResources": true, "composer.environments.get": true}
	return c
}

func TestViewerComposerPaginationAndProjection(t *testing.T) {
	searches, details := 0, 0
	c := composerClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		if r.URL.Host == "cloudasset.googleapis.com" {
			searches++
			if r.URL.Path != "/v1/projects/123:searchAllResources" || r.URL.Query().Get("assetTypes") != viewerComposerType || r.URL.Query().Get("readMask") != "name,assetType,project,location" {
				t.Fatal(r.URL)
			}
			if searches == 1 {
				return response(200, `{"results":[`+composerIndexOne+`],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"results":[`+composerIndexOne+`,{"name":"//composer.googleapis.com/projects/123/locations/europe-west1/environments/env-two","assetType":"composer.googleapis.com/Environment","project":"projects/123"}]}`), nil
		}
		if r.URL.Host != "composer.googleapis.com" || r.URL.Query().Get("fields") != viewerComposerFields || len(r.URL.Query()) != 1 {
			t.Fatal(r.URL)
		}
		details++
		if strings.HasSuffix(r.URL.Path, "/env-one") {
			return response(200, composerConfigOne), nil
		}
		if r.URL.Path != "/v1/projects/demo/locations/europe-west1/environments/env-two" {
			t.Fatal(r.URL)
		}
		return response(200, `{"name":"projects/123/locations/europe-west1/environments/env-two","executionOutput":"PRIVATE","config":{"executionOutput":"PRIVATE","dagGcsPrefix":"gs://do-not-follow/dags","airflowUri":"https://do-not-follow.invalid","softwareConfig":{"envVariables":{},"executionOutput":"PRIVATE"},"nodeConfig":{"network":"projects/demo/global/networks/default"},"webServerNetworkAccessControl":{"allowedIpRanges":[{"value":"0.0.0.0/0","description":"all","executionOutput":"PRIVATE"}]},"privateEnvironmentConfig":{"enablePrivateEnvironment":true,"enablePrivateBuildsOnly":true}}}`), nil
	})
	var s Snapshot
	c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
	if searches != 2 || details != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatal(s, searches, details)
	}
	if s.Assets[1].Name != "//composer.googleapis.com/projects/demo/locations/europe-west1/environments/env-two" || Str(Get(s.Assets[0].Resource.Data, "config", "softwareConfig", "envVariables", "APP_PASSWORD")) != "sample" {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("runtime output retained")
	}
}

func TestViewerComposerIndexScopeAndMalformed(t *testing.T) {
	for _, row := range []string{`null`, strings.Replace(composerIndexOne, "projects/demo/", "projects/other/", 1), strings.Replace(composerIndexOne, "projects/123", "projects/999", 1), strings.Replace(composerIndexOne, "\"location\":\"us-central1\"", "\"location\":42", 1), strings.Replace(composerIndexOne, "composer.googleapis.com/Environment", "other.googleapis.com/Environment", 1)} {
		c := composerClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "cloudasset.googleapis.com" {
				t.Fatal("invalid index triggered detail", r.URL)
			}
			return response(200, `{"results":[`+row+`]}`), nil
		})
		var s Snapshot
		c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(row, s)
		}
	}
}

func TestViewerComposerMalformedDetailAndMissingConfig(t *testing.T) {
	for _, body := range []string{`null`, strings.Replace(composerConfigOne, "projects/demo", "projects/other", 1), strings.Replace(composerConfigOne, "env-one", "another", 1), `{"name":"projects/demo/locations/us-central1/environments/env-one","config":[]}`, `{"name":"projects/demo/locations/us-central1/environments/env-one","config":{"softwareConfig":{"envVariables":{"x":42}}}}`} {
		c := composerClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "cloudasset.googleapis.com" {
				return response(200, `{"results":[`+composerIndexOne+`]}`), nil
			}
			return response(200, body), nil
		})
		var s Snapshot
		c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
	c := composerClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "cloudasset.googleapis.com" {
			return response(200, `{"results":[`+composerIndexOne+`]}`), nil
		}
		return response(200, `{"name":"projects/demo/locations/us-central1/environments/env-one"}`), nil
	})
	var s Snapshot
	c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "incomplete") || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerComposerLatePageFailureAndPermissions(t *testing.T) {
	for _, permission := range []string{"cloudasset.assets.searchAllResources", "composer.environments.get", "late-failure"} {
		c := composerClient(t, func(r *http.Request) (*http.Response, error) {
			if permission == "cloudasset.assets.searchAllResources" {
				t.Fatal("guard permitted search")
			}
			if r.URL.Host == "cloudasset.googleapis.com" {
				if r.URL.Query().Get("pageToken") != "" {
					return response(403, "PRIVATE"), nil
				}
				return response(200, `{"results":[`+composerIndexOne+`],"nextPageToken":"next"}`), nil
			}
			if permission == "composer.environments.get" {
				t.Fatal("guard permitted detail")
			}
			return response(200, composerConfigOne), nil
		})
		delete(c.viewerPolicy.permissions, permission)
		var s Snapshot
		c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || (permission == "late-failure" && len(s.Assets) != 1) {
			t.Fatal(s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal("error body leaked")
		}
	}
}

func TestViewerComposerUnreachableKeepsLaterPage(t *testing.T) {
	c := composerClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "composer.googleapis.com" {
			return response(200, composerConfigOne), nil
		}
		if r.URL.Query().Get("pageToken") == "" {
			return response(200, `{"unreachable":["us-west1"],"nextPageToken":"next"}`), nil
		}
		return response(200, `{"results":[`+composerIndexOne+`]}`), nil
	})
	var s Snapshot
	c.CollectViewerComposer(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Assets) != 1 {
		t.Fatal(s)
	}
}

func TestViewerComposerModernNetworkingProjection(t *testing.T) {
	if !strings.Contains(viewerComposerFields, "networkingType") {
		t.Fatal("modern networking configuration absent from API selector")
	}
	for _, value := range []any{"PUBLIC", "PRIVATE", true} {
		clean, err := viewerComposerProjection(Object{"config": Object{"privateEnvironmentConfig": Object{"networkingType": value, "enablePrivateEnvironment": false}}})
		if _, ok := value.(string); ok {
			if err != nil || Get(clean, "config", "privateEnvironmentConfig", "networkingType") != value {
				t.Fatal(clean, err)
			}
		} else if err == nil {
			t.Fatal("malformed networking type accepted")
		}
	}
}
