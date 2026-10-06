package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestGlobalIAPBackendDiscoveryPaginationAndProjectIdentity(t *testing.T) {
	listCalls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal(r.Method)
		}
		switch r.URL.Host {
		case "cloudresourcemanager.googleapis.com":
			return response(200, `{"name":"projects/123","projectId":"my-project","state":"ACTIVE"}`), nil
		case "compute.googleapis.com":
			if r.URL.Path != "/compute/v1/projects/my-project/global/backendServices" || r.URL.Query().Get("maxResults") != "500" {
				t.Fatal(r.URL)
			}
			listCalls++
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"warning":{"code":"NO_RESULTS_ON_PAGE"},"nextPageToken":"next"}`), nil
			}
			return response(200, `{"items":[{"name":"backend","selfLink":"https://www.googleapis.com/compute/v1/projects/my-project/global/backendServices/backend","protocol":"HTTP","iap":{"enabled":false}},{"name":"backend"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectIAPBackends(context.Background(), &s, []string{"projects/my-project", "projects/my-project", "projects/123", "folders/9"})
	if listCalls != 2 || len(s.Assets) != 2 || hasCoverage(s, "failed") {
		t.Fatal(listCalls, s)
	}
	a := s.Assets[1]
	if a.Name != "//compute.googleapis.com/projects/my-project/global/backendServices/backend" || a.Ancestors[0] != "projects/123" {
		t.Fatal(a)
	}
	paths, ok := iapTargets(a)
	if !ok || paths[len(paths)-1] != "projects/123/iap_web/compute/services/backend" {
		t.Fatal(paths)
	}
}

func TestGlobalIAPBackendPartialFailure(t *testing.T) {
	for _, bad := range []string{`null`, `{"items":{}}`, `{"items":[{"name":"../bad"}]}`, `{"items":[{"name":"backend","region":"regions/r"}]}`, `{"items":[{"name":"backend","selfLink":"https://evil.example/backend"}]}`, `{"nextPageToken":2}`, `{"nextPageToken":"next"}`, `{"warning":{"code":"UNREACHABLE","message":"PRIVATE_ERROR"}}`, "DENIED"} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "cloudresourcemanager.googleapis.com" {
				return response(200, `{"name":"projects/123","projectId":"my-project"}`), nil
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"items":[{"name":"known"}],"nextPageToken":"next"}`), nil
			}
			if bad == "DENIED" {
				return response(403, "PRIVATE_ERROR"), nil
			}
			return response(200, bad), nil
		})
		s := Snapshot{}
		c.CollectIAPBackends(context.Background(), &s, []string{"projects/123"})
		if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
			t.Fatal(bad, s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE_ERROR") {
			t.Fatal("upstream message leaked")
		}
	}
}

func TestGlobalIAPBackendRejectsProjectMismatch(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "cloudresourcemanager.googleapis.com" {
			t.Fatal("followed mismatched project")
		}
		return response(200, `{"name":"projects/999","projectId":"other-project"}`), nil
	})
	s := Snapshot{}
	c.CollectIAPBackends(context.Background(), &s, []string{"projects/123"})
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
