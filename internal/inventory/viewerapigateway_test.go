package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func apiGatewayClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"apigateway.apis.list": true, "apigateway.apiconfigs.list": true, "apigateway.apiconfigs.get": true, "apigateway.locations.list": true, "apigateway.gateways.list": true}
	return c
}
func apiGatewayConfigJSON() string {
	source := `{"swagger":"2.0","info":{"title":"DO_NOT_KEEP","version":"1"},"paths":{"/sensitive-path":{"get":{"security":[],"responses":{"200":{"description":"DO_NOT_KEEP"}}}}}}`
	return `{"name":"projects/123/locations/global/apis/example/configs/config","state":"ACTIVE","gatewayServiceAccount":"worker@demo.iam.gserviceaccount.com","openapiDocuments":[{"document":{"path":"DO_NOT_KEEP","contents":"` + base64.StdEncoding.EncodeToString([]byte(source)) + `"}}],"labels":{"secret":"DO_NOT_KEEP"}}`
}

func TestViewerAPIGatewayPaginationProjectionAuth(t *testing.T) {
	calls := map[string]int{}
	c := apiGatewayClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "apigateway.googleapis.com" {
			t.Fatal(r.URL)
		}
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/projects/demo/locations/global/apis":
			if r.URL.Query().Get("fields") != "apis(name,createTime,updateTime,state,managedService),nextPageToken,unreachableLocations" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"apis":[{"name":"projects/123/locations/global/apis/example","state":"ACTIVE","labels":{"x":"DO_NOT_KEEP"}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"apis":[{"name":"projects/demo/locations/global/apis/example"}]}`), nil
		case "/v1/projects/demo/locations/global/apis/example/configs":
			if r.URL.Query().Get("fields") != "apiConfigs("+viewerAPIGatewayConfigFields+"),nextPageToken,unreachableLocations" || r.URL.Query().Has("view") {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"apiConfigs":[{"name":"projects/demo/locations/global/apis/example/configs/config"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"apiConfigs":[{"name":"projects/demo/locations/global/apis/example/configs/config","openapiDocuments":[{"document":{"contents":"DO_NOT_KEEP"}}]}]}`), nil
		case "/v1/projects/demo/locations/global/apis/example/configs/config":
			if r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != viewerAPIGatewayFullFields {
				t.Fatal(r.URL)
			}
			return response(200, apiGatewayConfigJSON()), nil
		case "/v1/projects/demo/locations":
			if r.URL.Query().Get("fields") != "locations(name,locationId),nextPageToken" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1"},{"name":"projects/demo/locations/global"}]}`), nil
		case "/v1/projects/demo/locations/us-central1/gateways":
			if r.URL.Query().Get("fields") != "gateways(name,createTime,updateTime,state,apiConfig,defaultHostname),nextPageToken,unreachableLocations" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"gateways":[],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"gateways":[{"name":"projects/demo/locations/us-central1/gateways/gateway","state":"ACTIVE","apiConfig":"projects/demo/locations/global/apis/example/configs/config","defaultHostname":"example.gateway.dev","displayName":"DO_NOT_KEEP"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerAPIGateway(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if s.Assets[1].Resource.Data["_gcpbusterAuth"] == nil {
		t.Fatal(s.Assets[1])
	}
	b, _ := json.Marshal(s)
	for _, marker := range []string{"DO_NOT_KEEP", "sensitive-path", "openapiDocuments", "contents"} {
		if strings.Contains(string(b), marker) {
			t.Fatal(marker, string(b))
		}
	}
}

func TestViewerAPIGatewayPartialMalformedAndDeniedDetail(t *testing.T) {
	for _, mode := range []string{"permission", "server", "mismatch", "parse"} {
		t.Run(mode, func(t *testing.T) {
			c := apiGatewayClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v1/projects/demo/locations/global/apis":
					return response(200, `{"apis":[null,{"name":"projects/other/locations/global/apis/foreign"},{"name":"projects/demo/locations/global/apis/example"}],"unreachableLocations":["global"]}`), nil
				case "/v1/projects/demo/locations/global/apis/example/configs":
					return response(200, `{"apiConfigs":[{"name":"projects/demo/locations/global/apis/example/configs/config","state":"ACTIVE"}]}`), nil
				case "/v1/projects/demo/locations/global/apis/example/configs/config":
					if mode == "permission" {
						t.Fatal("unauthorized detail")
					}
					if mode == "server" {
						return response(403, `{}`), nil
					}
					if mode == "mismatch" {
						return response(200, `{"name":"projects/other/locations/global/apis/example/configs/config"}`), nil
					}
					return response(200, `{"name":"projects/demo/locations/global/apis/example/configs/config","state":"ACTIVE","openapiDocuments":[{"document":{"contents":"not base64 DO_NOT_KEEP"}}]}`), nil
				case "/v1/projects/demo/locations":
					return response(200, `{"locations":[{"name":"projects/foreign/locations/us-east1"},{"name":"projects/demo/locations/us-central1"}]}`), nil
				case "/v1/projects/demo/locations/us-central1/gateways":
					return response(200, `{"gateways":[{"name":"projects/demo/locations/us-central1/gateways/gateway"}]}`), nil
				default:
					t.Fatal(r.URL)
					return nil, nil
				}
			})
			if mode == "permission" {
				delete(c.viewerPolicy.permissions, "apigateway.apiconfigs.get")
			}
			s := Snapshot{}
			c.CollectViewerAPIGateway(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 3 || !hasCoverage(s, "failed") {
				t.Fatal(mode, s)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "DO_NOT_KEEP") {
				t.Fatal(string(b))
			}
		})
	}
}

func TestViewerAPIGatewayLateListFailureRetainsParents(t *testing.T) {
	lists := 0
	c := apiGatewayClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/apis") {
			lists++
			if lists == 1 {
				return response(200, `{"apis":[{"name":"projects/demo/locations/global/apis/example"}],"nextPageToken":"next"}`), nil
			}
			return response(403, `{}`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerAPIGateway(context.Background(), &s, "demo", "projects/123")
	if lists != 2 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(lists, s)
	}
}

func TestViewerAPIGatewayInvalidProjectNoTransport(t *testing.T) {
	c := apiGatewayClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerAPIGateway(context.Background(), &s, "demo/foreign", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
