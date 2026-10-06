package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestParameterMetadataWithoutPayloadCaptureAndConflicts(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/v1/projects/123/locations":
			return response(200, `{}`), nil
		case "/v1/projects/123/locations/global/parameters":
			if r.URL.Query().Get("fields") != parameterListFields {
				t.Fatal("metadata mask")
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"parameters":[{"name":"projects/123/locations/global/parameters/p","policyMember":{"iamPolicyUidPrincipal":"principal://parametermanager.googleapis.com/projects/123/uid/locations/global/parameters/uid1","unexpected":"SECRET_SENTINEL"},"labels":{"token":"SECRET_SENTINEL"}}],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"parameters":[{"name":"projects/123/locations/global/parameters/p","policyMember":{"iamPolicyUidPrincipal":"principal://parametermanager.googleapis.com/projects/123/uid/locations/global/parameters/uid2"}}]}`), nil
		default:
			t.Fatal("payload read without capture", r.URL)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions["parametermanager.locations.list"] = true
	c.viewerPolicy.permissions["parametermanager.parameters.list"] = true
	snap := Snapshot{}
	c.CollectViewerParameterManager(context.Background(), &snap, "demo", "projects/123")
	if calls != 3 || len(snap.Assets) != 1 || snap.Assets[0].Resource.Data["identityMetadataConflict"] != true || !hasCoverage(snap, "failed") {
		t.Fatal(calls, snap)
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "SECRET_SENTINEL") || strings.Contains(string(b), "uid1") || strings.Contains(string(b), "uid2") {
		t.Fatal("conflicting/unknown metadata persisted", string(b))
	}
}

func TestOfflineParameterPayloadStrictCapture(t *testing.T) {
	name := "projects/123/locations/global/parameters/p/versions/v1"
	a := NewAsset("//parametermanager.googleapis.com/"+name, "parametermanager.googleapis.com/ParameterVersion", Object{"name": name, "payload": Object{"data": base64.StdEncoding.EncodeToString([]byte(`key: __REF__("//secretmanager.googleapis.com/projects/456/secrets/s/versions/1")`))}})
	c := NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	if len(c.Samples()) != 1 || c.Samples()[0].SourceType != "parameter_manager_raw" {
		t.Fatal(c.Samples())
	}
	a.Resource.Data["disabled"] = true
	c = NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	if len(c.Samples()) != 0 {
		t.Fatal("disabled offline payload captured")
	}
}
