package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerAppCheckExplicitScopedMetadataPagination(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/resourcePolicies") {
			return response(200, `{}`), nil
		}
		calls++
		if r.Method != "GET" || r.URL.Host != "firebaseappcheck.googleapis.com" || r.URL.Path != "/v1/projects/123/services" || r.URL.Query().Get("fields") != viewerAppCheckFields || r.URL.Query().Get("pageSize") != "100" {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"services":[{"name":"projects/foreign/services/firestore.googleapis.com"},{"name":"projects/123/services/firestore.googleapis.com","enforcementMode":"UNENFORCED","replayProtection":"OFF","debugToken":"SENTINEL"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"services":[{"name":"projects/123/services/firebasestorage.googleapis.com"},{"name":"projects/123/services/firebasedatabase.googleapis.com","enforcementMode":"OFF|ENFORCED","replayProtection":"ENFORCED"}]}`), nil
	})
	var out Snapshot
	c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || len(out.Assets) != 3 || !hasCoverage(out, "failed") {
		t.Fatal(out)
	}
	if out.Assets[1].Resource.Data["enforcementMode"] != nil || out.Assets[2].Resource.Data["enforcementMode"] != nil {
		t.Fatal("missing/invalid mode defaulted")
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal("secret retained")
	}
}

func TestViewerAppCheckEmptyAndLateFailureRemainUnknown(t *testing.T) {
	for _, late := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/resourcePolicies") {
				return response(200, `{}`), nil
			}
			calls++
			if !late {
				return response(200, `{}`), nil
			}
			if calls == 1 {
				return response(200, `{"services":[{"name":"projects/123/services/firestore.googleapis.com","enforcementMode":"OFF"}],"nextPageToken":"next"}`), nil
			}
			return response(403, `SENTINEL`), nil
		})
		var out Snapshot
		c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
		if late {
			if len(out.Assets) != 1 || !hasCoverage(out, "failed") {
				t.Fatal(out)
			}
		} else if len(out.Assets) != 0 || hasCoverage(out, "failed") {
			t.Fatal(out)
		}
	}
}

func TestViewerAppCheckStrictReadGuardAndBaseline(t *testing.T) {
	endpoint := "https://firebaseappcheck.googleapis.com/v1/projects/123/services"
	q := url.Values{"fields": {viewerAppCheckFields}, "pageSize": {"100"}}
	permissions, e := viewerRequestPermissions("GET", endpoint, q)
	if e != nil || len(permissions) != 1 || permissions[0] != "firebaseappcheck.services.get" {
		t.Fatal(permissions, e)
	}
	for _, tc := range []struct {
		method, path string
		q            url.Values
	}{{"POST", endpoint, q}, {"GET", strings.Replace(endpoint, "123", "demo", 1), q}, {"GET", endpoint + "/firestore.googleapis.com", q}, {"GET", "https://firebaseappcheck.googleapis.com/v1/projects/123/apps/app/debugTokens", q}, {"POST", "https://firebaseappcheck.googleapis.com/v1/projects/123/apps/app:exchangeDebugToken", q}, {"GET", endpoint, url.Values{"fields": {"*"}, "pageSize": {"100"}}}, {"GET", endpoint, url.Values{"fields": {viewerAppCheckFields}, "pageSize": {"100", "100"}}}} {
		if _, err := viewerRequestPermissions(tc.method, tc.path, tc.q); err == nil {
			t.Fatal("unsafe allowed", tc.path)
		}
	}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("missing baseline reached transport")
		return nil, nil
	})
	delete(c.viewerPolicy.permissions, "firebaseappcheck.services.get")
	delete(c.viewerPolicy.permissions, "firebaseappcheck.resourcePolicies.get")
	var out Snapshot
	c.CollectViewerAppCheck(context.Background(), &out, "demo", "projects/123")
	if !hasCoverage(out, "failed") || len(out.Assets) != 0 {
		t.Fatal(out)
	}
}
