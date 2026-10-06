package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func appEngineProject() Asset {
	return NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", Object{"projectId": "my-project"})
}

func TestAppEngineIAPDiscovery(t *testing.T) {
	services, versions := 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/apps/my-project" {
			return response(200, `{"name":"apps/my-project","id":"my-project","iap":{"enabled":false}}`), nil
		}
		if r.Method != "GET" || r.URL.Host != "appengine.googleapis.com" {
			t.Fatal(r.URL)
		}
		if r.URL.Path == "/v1/apps/my-project/services" {
			services++
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"nextPageToken":"more"}`), nil
			}
			return response(200, `{"services":[{"id":"default","name":"apps/my-project/services/default"},{"id":"default","name":"apps/my-project/services/default"}]}`), nil
		}
		if r.URL.Path != "/v1/apps/my-project/services/default/versions" || r.URL.Query().Get("view") != "BASIC" {
			t.Fatal(r.URL)
		}
		versions++
		return response(200, `{"versions":[{"id":"v1","name":"apps/my-project/services/default/versions/v1","envVariables":{"PASSWORD":"PRIVATE_PAYLOAD"}}]}`), nil
	})
	s := Snapshot{Assets: []Asset{appEngineProject(), appEngineProject()}}
	c.CollectAppEngineIAP(context.Background(), &s)
	if services != 2 || versions != 1 || len(s.Assets) != 5 || hasCoverage(s, "failed") {
		t.Fatal(services, versions, s)
	}
	paths, ok := iapTargets(s.Assets[4])
	if !ok || len(paths) != 5 || paths[4] != "projects/123/iap_web/appengine-my-project/services/default/versions/v1" {
		t.Fatal(paths)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE_PAYLOAD") {
		t.Fatal("unneeded payload retained")
	}
}

func TestAppEngineIAPPartialFailure(t *testing.T) {
	for _, bad := range []string{`null`, `{"versions":{}}`, `{"nextPageToken":1}`, `{"nextPageToken":"more"}`, `{"versions":[{"id":"v2","name":"apps/other/services/default/versions/v2"}]}`, "DENIED"} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/v1/apps/my-project" {
				return response(200, `{"name":"apps/my-project","id":"my-project"}`), nil
			}
			if strings.HasSuffix(r.URL.Path, "/services") {
				return response(200, `{"services":[{"id":"default","name":"apps/my-project/services/default"}]}`), nil
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"versions":[{"id":"v1","name":"apps/my-project/services/default/versions/v1"}],"nextPageToken":"more"}`), nil
			}
			if bad == "DENIED" {
				return response(403, "PRIVATE_ERROR"), nil
			}
			return response(200, bad), nil
		})
		s := Snapshot{Assets: []Asset{appEngineProject()}}
		c.CollectAppEngineIAP(context.Background(), &s)
		if len(s.Assets) != 4 || !hasCoverage(s, "failed") {
			t.Fatal(bad, s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE_ERROR") {
			t.Fatal("error leaked")
		}
	}
}

func TestAppEngineIAPTargetsRejectMalformedHierarchy(t *testing.T) {
	for _, path := range []string{"apps/my-project/versions/v1", "apps/my-project/services/default", "apps/my-project/services/default/versions/../v1"} {
		a := NewAsset("//appengine.googleapis.com/"+path, "appengine.googleapis.com/Version", nil)
		a.Ancestors = []string{"projects/123"}
		if _, ok := iapTargets(a); ok {
			t.Fatal(path)
		}
	}
}

func TestAppEngineAppReadFailureRetainsServiceDiscovery(t *testing.T) {
	for _, bad := range []string{`null`, `{"name":"apps/other","id":"other"}`, "DENIED"} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/v1/apps/my-project" {
				if bad == "DENIED" {
					return response(403, "PRIVATE_ERROR"), nil
				}
				return response(200, bad), nil
			}
			if strings.HasSuffix(r.URL.Path, "/services") {
				return response(200, `{"services":[{"id":"default","name":"apps/my-project/services/default","networkSettings":{"ingressTrafficAllowed":"INGRESS_TRAFFIC_ALLOWED_INTERNAL_ONLY"}}]}`), nil
			}
			return response(200, `{}`), nil
		})
		s := Snapshot{Assets: []Asset{appEngineProject()}}
		c.CollectAppEngineIAP(context.Background(), &s)
		if !hasCoverage(s, "failed") || len(s.Assets) != 3 || Str(Get(s.Assets[2].Resource.Data, "networkSettings", "ingressTrafficAllowed")) != "INGRESS_TRAFFIC_ALLOWED_INTERNAL_ONLY" {
			t.Fatal(bad, s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE_ERROR") {
			t.Fatal("error leaked")
		}
	}
}
