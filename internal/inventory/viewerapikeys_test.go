package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerAPIKeysPaginationMetadataOnly(t *testing.T) {
	pages := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		pages++
		if r.Method != "GET" || r.URL.Host != "apikeys.googleapis.com" || r.URL.Path != "/v2/projects/123/locations/global/keys" || r.URL.Query().Get("showDeleted") != "false" {
			t.Fatal("unexpected key endpoint", r.Method, r.URL)
		}
		if pages == 1 {
			return response(200, `{"keys":[],"nextPageToken":"more"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "more" {
			t.Fatal("missing page token")
		}
		return response(200, `{"keys":[{"name":"projects/123/locations/global/keys/key-one","restrictions":{"apiTargets":[{"service":"maps.googleapis.com"}]},"keyString":"DO_NOT_RETAIN_KEY_STRING"}]}`), nil
	})
	// Only metadata permission: deliberately no getKeyString/get permission.
	c.viewerPolicy.permissions = map[string]bool{"apikeys.keys.list": true}
	var s Snapshot
	c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
	if pages != 2 || len(s.Assets) != 1 || hasCoverage(s, "failed") || s.Assets[0].Name != "//apikeys.googleapis.com/projects/demo/locations/global/keys/key-one" || Str(s.Assets[0].Resource.Data["name"]) != "projects/123/locations/global/keys/key-one" {
		t.Fatal(s, pages)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_RETAIN") || len(List(Get(s.Assets[0].Resource.Data, "restrictions", "apiTargets"))) != 1 {
		t.Fatal("key material persisted or restrictions lost")
	}
}

func TestViewerAPIKeysRejectsMalformedOrForeignEvidence(t *testing.T) {
	for _, body := range []string{`{"keys":{}}`, `{"keys":[null]}`, `{"keys":[{"name":"projects/999/locations/global/keys/key-one"}]}`, `{"keys":[{"name":"projects/123/locations/us-central1/keys/key-one"}]}`, `{"keys":[{"name":"projects/123/locations/global/keys/key-one","restrictions":42}]}`, `{"keys":[{"name":"projects/123/locations/global/keys/key-one","deleteTime":"2025-01-01T00:00:00Z"}]}`, `{"nextPageToken":3}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerAPIKeysPartialAndPermissionDenial(t *testing.T) {
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"keys":[{"name":"projects/123/locations/global/keys/good"}],"nextPageToken":"denied"}`), nil
		}
		return response(403, "DO_NOT_RETAIN_ERROR"), nil
	})
	var s Snapshot
	c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_RETAIN") {
		t.Fatal("upstream body leaked")
	}
	c.viewerPolicy.permissions = map[string]bool{"iam.roles.get": true}
	before := calls
	s = Snapshot{}
	c.CollectViewerAPIKeys(context.Background(), &s, "demo", "projects/123")
	if calls != before || !hasCoverage(s, "failed") {
		t.Fatal("missing permission reached transport")
	}
	c.CollectViewerAPIKeys(context.Background(), &s, "../bad", "projects/123")
	if calls != before {
		t.Fatal("invalid scope reached transport")
	}
}

func TestViewerQualifiedPermissionSyntaxPreservesExactNames(t *testing.T) {
	for _, permission := range []string{"iam.roles.get", "iam.googleapis.com/workloadIdentityPools.list"} {
		if !viewerPermissionName.MatchString(permission) {
			t.Fatal("valid permission rejected", permission)
		}
	}
	for _, permission := range []string{"*", "iam.googleapis.com/*", "iam.googleapis.com/../list", "iam.googleapis.com/pools/list", "iam.googleapis.com/pools.list\n", "iam.googleapis.com/pools.list?override=yes"} {
		if viewerPermissionName.MatchString(permission) {
			t.Fatal("invalid permission accepted", permission)
		}
	}
	t.Setenv("QUALIFIED_ROLE_TOKEN", "test")
	c := Client{TokenEnv: "QUALIFIED_ROLE_TOKEN", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "iam.googleapis.com" || !strings.HasPrefix(r.URL.Path, "/v1/roles/") {
			t.Fatal(r.URL)
		}
		b, _ := json.Marshal(Object{"name": strings.TrimPrefix(r.URL.Path, "/v1/"), "includedPermissions": []string{"apikeys.keys.list", "iam.googleapis.com/workloadIdentityPools.list"}})
		return response(200, string(b)), nil
	})}}
	if err := c.requireViewerPermissions(context.Background(), "GET", "https://apikeys.googleapis.com/v2/projects/123/locations/global/keys", nil); err != nil {
		t.Fatal(err)
	}
	if c.viewerPolicy.permissions["iam.workloadIdentityPools.list"] {
		t.Fatal("invented permission alias")
	}
}
