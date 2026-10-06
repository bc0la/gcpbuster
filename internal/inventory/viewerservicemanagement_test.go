package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func serviceManagementClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"servicemanagement.services.list": true, "servicemanagement.services.get": true}
	return c
}
func compiledServiceFixture() string {
	return `{"name":"example.endpoints.demo.cloud.goog","id":"config-1","producerProjectId":"demo","apis":[{"name":"SENSITIVE_API","methods":[{"name":"SENSITIVE_METHOD"}]}],"authentication":{"rules":[{"selector":"*","requirements":[]}]},"usage":{"rules":[{"selector":"*","allowUnregisteredCalls":true}]},"backend":{"rules":[{"selector":"*","address":"https://DO_NOT_KEEP.invalid"}]},"sourceInfo":{"sourceFiles":[{"contents":"DO_NOT_KEEP"}]},"documentation":{"summary":"DO_NOT_KEEP"}}`
}

func TestViewerServiceManagementPaginationProducerScopeProjection(t *testing.T) {
	calls := map[string]int{}
	c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "servicemanagement.googleapis.com" {
			t.Fatal(r.URL)
		}
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/services":
			if r.URL.Query().Get("producerProjectId") != "demo" || r.URL.Query().Get("fields") != "services(serviceName,producerProjectId),nextPageToken" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"services":[{"serviceName":"example.endpoints.demo.cloud.goog"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"services":[{"serviceName":"example.endpoints.demo.cloud.goog","producerProjectId":"demo"}]}`), nil
		case "/v1/services/example.endpoints.demo.cloud.goog":
			if r.URL.Query().Get("fields") != "serviceName,producerProjectId" {
				t.Fatal(r.URL)
			}
			return response(200, `{"serviceName":"example.endpoints.demo.cloud.goog","producerProjectId":"demo","unknown":"DO_NOT_KEEP"}`), nil
		case "/v1/services/example.endpoints.demo.cloud.goog/configs":
			if r.URL.Query().Get("fields") != "serviceConfigs(name,id,producerProjectId),nextPageToken" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"serviceConfigs":[{"id":"config-1"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"serviceConfigs":[{"name":"example.endpoints.demo.cloud.goog","id":"config-1"}]}`), nil
		case "/v1/services/example.endpoints.demo.cloud.goog/configs/config-1":
			if r.URL.Query().Get("view") != "BASIC" || r.URL.Query().Get("fields") != viewerServiceConfigFields {
				t.Fatal(r.URL)
			}
			return response(200, compiledServiceFixture()), nil
		case "/v1/services/example.endpoints.demo.cloud.goog/rollouts":
			return response(200, `{}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerServiceManagement(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || hasCoverage(s, "failed") || s.Assets[1].Resource.Data["_gcpbusterServiceAuth"] == nil {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	for _, marker := range []string{"DO_NOT_KEEP", "SENSITIVE_API", "SENSITIVE_METHOD", "sourceInfo"} {
		if strings.Contains(string(b), marker) {
			t.Fatal(marker, string(b))
		}
	}
}

func TestViewerServiceManagementUnconfirmedProducerStopsConfigReads(t *testing.T) {
	for _, mode := range []string{"foreign", "missing", "denied", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/v1/services" {
					return response(200, `{"services":[null,{"serviceName":"https://evil.invalid"},{"serviceName":"other.example.com","producerProjectId":"other"},{"serviceName":"example.endpoints.demo.cloud.goog"}]}`), nil
				}
				if strings.Contains(r.URL.Path, "/configs") {
					t.Fatal("unconfirmed service followed", r.URL)
				}
				switch mode {
				case "foreign":
					return response(200, `{"serviceName":"example.endpoints.demo.cloud.goog","producerProjectId":"other"}`), nil
				case "missing":
					return response(200, `{"serviceName":"example.endpoints.demo.cloud.goog"}`), nil
				case "mismatch":
					return response(200, `{"serviceName":"another.example.com","producerProjectId":"demo"}`), nil
				default:
					return response(403, `{}`), nil
				}
			})
			s := Snapshot{}
			c.CollectViewerServiceManagement(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerServiceManagementConfigFailurePreservesMetadata(t *testing.T) {
	for _, mode := range []string{"server", "mismatch", "producer", "late-list"} {
		t.Run(mode, func(t *testing.T) {
			c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v1/services":
					return response(200, `{"services":[{"serviceName":"example.endpoints.demo.cloud.goog"}]}`), nil
				case "/v1/services/example.endpoints.demo.cloud.goog":
					return response(200, `{"serviceName":"example.endpoints.demo.cloud.goog","producerProjectId":"demo"}`), nil
				case "/v1/services/example.endpoints.demo.cloud.goog/configs":
					if r.URL.Query().Get("pageToken") != "" {
						return response(403, `{}`), nil
					}
					next := ""
					if mode == "late-list" {
						next = `,"nextPageToken":"next"`
					}
					return response(200, `{"serviceConfigs":[{"id":"../foreign"},{"id":"config-1"}]`+next+`}`), nil
				default:
					if mode == "server" {
						return response(403, `{}`), nil
					}
					if mode == "mismatch" {
						return response(200, `{"name":"foreign.example.com","id":"config-1"}`), nil
					}
					if mode == "producer" {
						return response(200, `{"name":"example.endpoints.demo.cloud.goog","id":"config-1","producerProjectId":"other"}`), nil
					}
					return response(200, compiledServiceFixture()), nil
				}
			})
			s := Snapshot{}
			c.CollectViewerServiceManagement(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerServiceManagementPermissionAndScopeFailClosed(t *testing.T) {
	for _, mode := range []string{"permission", "scope"} {
		c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
		project := "demo"
		if mode == "permission" {
			c.viewerPolicy.permissions = map[string]bool{}
		} else {
			project = "demo/other"
		}
		s := Snapshot{}
		c.CollectViewerServiceManagement(context.Background(), &s, project, "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(mode, s)
		}
	}
}
