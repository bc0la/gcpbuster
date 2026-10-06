package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func appEngineClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"appengine.applications.get": true, "appengine.services.list": true, "appengine.versions.list": true, "appengine.versions.get": true}
	return c
}

func TestViewerAppEngineScopedFullProjection(t *testing.T) {
	services, versions := 0, 0
	c := appEngineClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "appengine.googleapis.com" {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/apps/demo":
			if r.URL.Query().Get("fields") != viewerAppEngineApplicationFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"apps/demo","id":"demo","iap":{"enabled":false,"oauth2ClientSecret":"SENTINEL","oauth2ClientSecretSha256":"SENTINEL"}}`), nil
		case "/v1/apps/demo/services":
			services++
			if r.URL.Query().Get("fields") != "services("+viewerAppEngineServiceFields+"),nextPageToken" {
				t.Fatal(r.URL)
			}
			if services == 1 {
				return response(200, `{"services":[{"name":"apps/demo/services/default","networkSettings":{"ingressTrafficAllowed":"INGRESS_TRAFFIC_ALLOWED_ALL","unknown":"SENTINEL"}}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{}`), nil
		case "/v1/apps/demo/services/default/versions":
			versions++
			if r.URL.Query().Get("view") != "BASIC" || r.URL.Query().Get("fields") != "versions("+viewerAppEngineVersionFields+"),nextPageToken" {
				t.Fatal(r.URL)
			}
			if versions == 1 {
				return response(200, `{"versions":[{"name":"apps/demo/services/default/versions/v1","runtime":"python313"}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{}`), nil
		case "/v1/apps/demo/services/default/versions/v1":
			if r.URL.Query().Get("view") != "FULL" || r.URL.Query().Get("fields") != viewerAppEngineFullFields {
				t.Fatal(r.URL)
			}
			return response(200, `{"name":"apps/demo/services/default/versions/v1","runtime":"python313","serviceAccount":"worker@demo.iam.gserviceaccount.com","envVariables":{"PASSWORD":"SENTINEL"},"buildEnvVariables":{"API_TOKEN":"SENTINEL"},"deployment":{"files":{"SENTINEL":{"sourceUrl":"https://example.test/SENTINEL"}}},"network":{"name":"default","sessionAffinity":false,"unknown":"SENTINEL"}}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	out := Snapshot{}
	c.CollectViewerAppEngine(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 3 || services != 2 || versions != 2 || hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[2].Resource.Data["serviceAccount"] != "worker@demo.iam.gserviceaccount.com" {
		t.Fatal(out.Assets)
	}
	b, _ := json.Marshal(out)
	if candidates, ok := out.Assets[2].Resource.Data["_gcpbusterSecretCandidates"].([]any); !ok || len(candidates) != 2 {
		t.Fatal(out.Assets[2])
	}
	for _, s := range []string{"SENTINEL", "oauth2ClientSecret", "sourceUrl", `"envVariables":`, `"buildEnvVariables":`} {
		if strings.Contains(string(b), s) {
			t.Fatalf("leak %s: %s", s, b)
		}
	}
}

func TestViewerAppEngineIndependentDenialsAndMalformed(t *testing.T) {
	for _, mode := range []string{"application-denied", "full-denied", "full-foreign", "malformed", "late-services", "late-versions", "permission"} {
		t.Run(mode, func(t *testing.T) {
			c := appEngineClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v1/apps/demo":
					if mode == "application-denied" {
						return response(403, `{}`), nil
					}
					return response(200, `{"name":"apps/demo","iap":{"enabled":true}}`), nil
				case "/v1/apps/demo/services":
					if r.URL.Query().Get("pageToken") != "" {
						return response(403, `{}`), nil
					}
					next := ""
					if mode == "late-services" {
						next = `,"nextPageToken":"next"`
					}
					return response(200, `{"services":[null,{"name":"apps/foreign/services/evil"},{"name":"apps/demo/services/default"}]`+next+`}`), nil
				case "/v1/apps/demo/services/default/versions":
					if r.URL.Query().Get("pageToken") != "" {
						return response(403, `{}`), nil
					}
					next := ""
					if mode == "late-versions" {
						next = `,"nextPageToken":"next"`
					}
					return response(200, `{"versions":[{"name":"apps/demo/services/default/versions/v1","runtime":"python313"},{"name":"apps/demo/services/foreign/versions/bad"}]`+next+`}`), nil
				case "/v1/apps/demo/services/default/versions/v1":
					if mode == "permission" {
						t.Fatal("permission guard bypass")
					}
					if mode == "full-denied" {
						return response(403, `{}`), nil
					}
					if mode == "full-foreign" {
						return response(200, `{"name":"apps/foreign/services/default/versions/v1","runtime":"evil"}`), nil
					}
					if mode == "malformed" {
						return response(200, `{"name":"apps/demo/services/default/versions/v1","runtime":false,"vm":true,"envVariables":false}`), nil
					}
					return response(200, `{"name":"apps/demo/services/default/versions/v1","runtime":"python313"}`), nil
				default:
					t.Fatal(r.URL)
					return nil, nil
				}
			})
			if mode == "permission" {
				delete(c.viewerPolicy.permissions, "appengine.versions.get")
			}
			out := Snapshot{}
			c.CollectViewerAppEngine(context.Background(), &out, "demo", "projects/123")
			want := 3
			if mode == "application-denied" {
				want = 2
			}
			if len(out.Assets) != want || !hasCoverage(out, "failed") {
				t.Fatal(out)
			}
			last := out.Assets[len(out.Assets)-1]
			if last.Resource.Data["runtime"] != "python313" {
				t.Fatal(last)
			}
		})
	}
}

func TestViewerAppEngineRejectInvalidScope(t *testing.T) {
	c := appEngineClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	out := Snapshot{}
	c.CollectViewerAppEngine(context.Background(), &out, "../foreign", "projects/123")
	if len(out.Assets) != 0 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
}
