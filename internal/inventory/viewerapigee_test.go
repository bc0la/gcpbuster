package inventory

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func viewerApigeeTestBundle(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, body := range map[string]string{"apiproxy/demo.xml": `<APIProxy name="demo"/>`, "apiproxy/policies/auth.xml": `<VerifyAPIKey name="auth" enabled="false"><APIKey ref="request.header.secret"/></VerifyAPIKey>`, "apiproxy/proxies/default.xml": `<ProxyEndpoint name="default"><PreFlow><Request><Step><Name>auth</Name></Step></Request></PreFlow></ProxyEndpoint>`} {
		f, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(body)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestViewerApigeeScopedDeploymentRoutingAndSource(t *testing.T) {
	bundle := viewerApigeeTestBundle(t)
	downloads, groupPages, attachmentPages := 0, 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "apigee.googleapis.com" {
			t.Fatal(r.URL)
		}
		if strings.Contains(r.URL.Path, "/flowhooks/") {
			return response(200, `{}`), nil
		}
		switch r.URL.Path {
		case "/v1/organizations/demo/apiproducts":
			return response(200, `{}`), nil
		case "/v1/organizations/demo":
			return response(200, `{"name":"demo","projectId":"demo","properties":{"secret":"SENTINEL"}}`), nil
		case "/v1/organizations/demo/envgroups":
			groupPages++
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"environmentGroups":[{"name":"group","state":"ACTIVE","hostnames":["api.example.com"],"secret":"SENTINEL"}],"nextPageToken":"two"}`), nil
			}
			return response(200, `{}`), nil
		case "/v1/organizations/demo/envgroups/group/attachments":
			attachmentPages++
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"environmentGroupAttachments":[{"name":"bad","environment":"other/project"}],"nextPageToken":"two"}`), nil
			}
			return response(200, `{"environmentGroupAttachments":[{"name":"valid","environment":"prod","environmentGroupId":"group"}]}`), nil
		case "/v1/organizations/demo/deployments":
			return response(200, `{"deployments":[{"apiProxy":"bad/path","revision":"1","environment":"prod"},{"apiProxy":"api","revision":"3","environment":"prod","state":"READY","secret":"SENTINEL"},{"apiProxy":"api","revision":"3","environment":"test"}]}`), nil
		case "/v1/organizations/demo/apis/api/revisions/3":
			downloads++
			if r.URL.RawQuery != "format=bundle" {
				t.Fatal(r.URL)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(bundle)), Header: make(http.Header)}, nil
		}
		t.Fatalf("unexpected %s", r.URL)
		return nil, nil
	})
	c.SecretCapture = NewSecretCapture(10000, 4<<20, 64<<20)
	var out Snapshot
	c.CollectViewerApigee(context.Background(), &out, "demo", "projects/123")
	if len(c.SecretCapture.Samples()) == 0 {
		t.Fatal("validated already-read bundle not captured")
	}
	if downloads != 1 || groupPages != 2 || attachmentPages != 2 || len(out.Assets) != 3 {
		t.Fatalf("downloads %d pages %d/%d assets %d", downloads, groupPages, attachmentPages, len(out.Assets))
	}
	a := out.Assets[2]
	if a.Type != ApigeeProxyRevisionType || len(a.Resource.Data["deployments"].([]any)) != 2 || a.Resource.Data["_gcpbusterApigeeAuth"] == nil {
		t.Fatalf("%+v", a)
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{"SENTINEL", "request.header.secret", "<VerifyAPIKey"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("raw source retained: %s", secret)
		}
	}
}

func TestViewerApigeeBindingDenialAndPartialRetention(t *testing.T) {
	for _, binding := range []string{`{"name":"demo","projectId":"foreign"}`, `{}`} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) { calls++; return response(200, binding), nil })
		var out Snapshot
		c.CollectViewerApigee(context.Background(), &out, "demo", "projects/123")
		if calls != 1 || len(out.Assets) != 0 {
			t.Fatal("unverified organization followed")
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Path == "/v1/organizations/demo":
			return response(200, `{"name":"demo","projectId":"demo"}`), nil
		case strings.HasSuffix(r.URL.Path, "/envgroups"):
			return response(200, `{}`), nil
		case strings.HasSuffix(r.URL.Path, "/deployments"):
			return response(200, `{"deployments":[{"apiProxy":"api","revision":"1","environment":"prod"}]}`), nil
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("SENSITIVE_DENIAL"))}, nil
	})
	var out Snapshot
	c.CollectViewerApigee(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 1 || out.Assets[0].Resource.Data["_gcpbusterApigeeAuth"] != nil {
		t.Fatal(out)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("SENSITIVE_DENIAL")) {
		t.Fatal("error body leaked")
	}
}

func TestViewerApigeeBundleGuardAndBounds(t *testing.T) {
	endpoint := "https://apigee.googleapis.com/v1/organizations/demo/apis/api/revisions/1"
	for _, tc := range []struct {
		method, path string
		q            url.Values
	}{{"POST", endpoint, url.Values{"format": {"bundle"}}}, {"GET", endpoint, url.Values{"format": {"bundle"}, "fields": {"*"}}}, {"GET", endpoint, url.Values{"format": {"bundle", "bundle"}}}, {"GET", endpoint, nil}, {"GET", "https://apigee.googleapis.com/v1/organizations/demo/developers/a/apps/b", nil}, {"GET", "https://apigee.googleapis.com/v1/organizations/demo/environments/prod/keyvaluemaps/a/entries", nil}, {"GET", "https://apigee.googleapis.com/v1/organizations/demo/environments/prod/apis/api/revisions/1/debugsessions", nil}} {
		if _, e := viewerRequestPermissions(tc.method, tc.path, tc.q); e == nil {
			t.Fatalf("allowed %s", tc.path)
		}
	}
	for _, status := range []int{200, 302} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://attacker.example/source"}}, Body: io.NopCloser(io.LimitReader(infiniteApigeeBytes{}, viewerApigeeBundleLimit+1))}, nil
		})
		if _, e := c.viewerApigeeBundle(context.Background(), "organizations/demo/apis/api/revisions/1"); e == nil || calls != 1 {
			t.Fatalf("unbounded/redirect accepted: %v calls%d", e, calls)
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("missing baseline permission reached transport")
		return nil, nil
	})
	delete(c.viewerPolicy.permissions, "apigee.proxyrevisions.get")
	if _, e := c.viewerApigeeBundle(context.Background(), "organizations/demo/apis/api/revisions/1"); e == nil {
		t.Fatal("permission not gated")
	}
}

type infiniteApigeeBytes struct{}

func (infiniteApigeeBytes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}
