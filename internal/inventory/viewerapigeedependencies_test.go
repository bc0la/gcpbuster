package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerApigeeHooksSameEnvironmentRevisionOnly(t *testing.T) {
	bundle := apigeeTestBundle(t, [][2]string{{"sharedflowbundle/policies/auth.xml", `<VerifyJWT name="auth" enabled="false"/>`}, {"sharedflowbundle/sharedflows/default.xml", `<SharedFlow name="default"><Step><Name>auth</Name></Step></SharedFlow>`}})
	downloads, lists := 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		if strings.Contains(p, "/flowhooks/") {
			if r.URL.Query().Get("fields") != viewerApigeeHookFields {
				t.Fatal(r.URL)
			}
			if strings.HasSuffix(p, "PreProxyFlowHook") || strings.HasSuffix(p, "PreTargetFlowHook") {
				return response(200, `{"sharedFlow":"authflow","continueOnError":false,"description":"SENTINEL"}`), nil
			}
			return response(200, `{}`), nil
		}
		if p == "/v1/organizations/demo/sharedflows/authflow/deployments" {
			lists++
			return response(200, `{"deployments":[{"apiProxy":"authflow","environment":"other","revision":"99"},{"apiProxy":"authflow","environment":"prod","revision":"2","state":"READY"}]}`), nil
		}
		if p == "/v1/organizations/demo/sharedflows/authflow/revisions/2" {
			downloads++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(bundle))}, nil
		}
		t.Fatal("unobserved request", r.URL)
		return nil, nil
	})
	var out Snapshot
	deps := c.viewerApigeeDependencies(context.Background(), &out, "organizations/demo", map[string][]any{"organizations/demo/apis/api/revisions/1": {Object{"environment": "prod"}}})
	if downloads != 1 || lists != 1 {
		t.Fatalf("not deduplicated: %d/%d", downloads, lists)
	}
	hooks := deps["prod"]["hooks"].([]any)
	for _, i := range []int{0, 2} {
		h := Obj(hooks[i])
		if h["status"] != "present" || h["complete"] != true || len(h["revisions"].([]any)) != 1 || Obj(h["revisions"].([]any)[0])["auth"] == nil {
			t.Fatal(h)
		}
	}
	if Obj(hooks[1])["status"] != "absent" {
		t.Fatal(hooks)
	}
	raw, _ := json.Marshal(deps)
	if bytes.Contains(raw, []byte("SENTINEL")) || bytes.Contains(raw, []byte("<VerifyJWT")) || bytes.Contains(raw, []byte("/revisions/99")) {
		t.Fatal("raw/foreign source retained")
	}
}

func TestViewerApigeeHookErrorsAndAmbiguousRevisionsStayUnknown(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "PreProxyFlowHook"):
			return response(200, `null`), nil
		case strings.HasSuffix(p, "PostProxyFlowHook"):
			return response(403, `SENTINEL`), nil
		case strings.HasSuffix(p, "PreTargetFlowHook"):
			return response(200, `{"sharedFlow":"../outside"}`), nil
		case strings.HasSuffix(p, "PostTargetFlowHook"):
			return response(200, `{"sharedFlow":"authflow"}`), nil
		case strings.HasSuffix(p, "/deployments"):
			return response(200, `{"deployments":[{"environment":"other","revision":"3"}]}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	var out Snapshot
	deps := c.viewerApigeeDependencies(context.Background(), &out, "organizations/demo", map[string][]any{"proxy": {Object{"environment": "prod"}}})
	hooks := deps["prod"]["hooks"].([]any)
	for _, i := range []int{0, 1, 2} {
		if Obj(hooks[i])["status"] != "error" {
			t.Fatal(hooks)
		}
	}
	if Obj(hooks[3])["status"] != "present" || Obj(hooks[3])["complete"] != false {
		t.Fatal(hooks)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("SENTINEL")) {
		t.Fatal("error leaked")
	}
}

func TestViewerApigeeDependencyStrictGuard(t *testing.T) {
	hook := "https://apigee.googleapis.com/v1/organizations/demo/environments/prod/flowhooks/PreProxyFlowHook"
	q := url.Values{"fields": {viewerApigeeHookFields}}
	p, e := viewerRequestPermissions("GET", hook, q)
	if e != nil || len(p) != 1 || p[0] != "apigee.flowhooks.getSharedFlow" {
		t.Fatal(p, e)
	}
	for _, tc := range []struct {
		method, path string
		q            url.Values
	}{{"POST", hook, q}, {"GET", strings.Replace(hook, "PreProxyFlowHook", "unknown", 1), q}, {"GET", hook, url.Values{"fields": {"*"}}}, {"GET", "https://apigee.googleapis.com/v1/organizations/demo/sharedflows/auth/revisions/latest", url.Values{"format": {"bundle"}}}, {"GET", "https://apigee.googleapis.com/v1/organizations/demo/sharedflows/auth/revisions/1", url.Values{"format": {"bundle"}, "alt": {"media"}}}} {
		if _, e := viewerRequestPermissions(tc.method, tc.path, tc.q); e == nil {
			t.Fatal("unsafe request allowed", tc.path)
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("missing permission reached transport")
		return nil, nil
	})
	delete(c.viewerPolicy.permissions, "apigee.sharedflowrevisions.get")
	if _, e := c.viewerApigeeBundle(context.Background(), "organizations/demo/sharedflows/auth/revisions/1"); e == nil {
		t.Fatal("baseline not enforced")
	}
}
