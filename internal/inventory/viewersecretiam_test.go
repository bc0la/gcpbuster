package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func secretIAMAsset(name string) Asset {
	return NewAsset("//secretmanager.googleapis.com/"+name, "secretmanager.googleapis.com/Secret", Object{"name": name, "rotation": Object{"rotationPeriod": "86400s"}})
}
func secretIAMClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"secretmanager.secrets.getIamPolicy": true}
	return c
}

func TestViewerSecretIAMGlobalRegionalConditionsAndDuplicates(t *testing.T) {
	calls := 0
	c := secretIAMClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Query().Get("options.requestedPolicyVersion") != "3" || r.URL.Query().Get("fields") != "version,bindings,etag,auditConfigs" {
			t.Fatal(r.URL)
		}
		switch r.URL.Host + r.URL.Path {
		case "secretmanager.googleapis.com/v1/projects/123/secrets/global:getIamPolicy":
			return response(200, `{"version":3,"bindings":[{"role":"roles/secretmanager.secretAccessor","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')","title":"expiry"}}],"payload":"PRIVATE","_gcpbusterBindingsOnly":true}`), nil
		case "secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets/regional:getIamPolicy":
			return response(200, `{}`), nil
		default:
			t.Fatal("unexpected host/path", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{Assets: []Asset{secretIAMAsset("projects/123/secrets/global"), secretIAMAsset("projects/123/locations/us-central1/secrets/regional"), secretIAMAsset("projects/123/secrets/global"), secretIAMAsset("projects/999/secrets/foreign")}}
	c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || hasCoverage(s, "failed") || s.Assets[1].IAM == nil || s.Assets[3].IAM != nil {
		t.Fatal(s, calls)
	}
	for _, i := range []int{0, 2} {
		if s.Assets[i].IAM["version"] != float64(3) || Str(Get(Obj(List(s.Assets[i].IAM["bindings"])[0]), "condition", "expression")) == "" || Bool(s.Assets[i].IAM["_gcpbusterBindingsOnly"]) {
			t.Fatal(s.Assets[i])
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal(string(b))
	}
}

func TestViewerSecretIAMMalformedPolicyPreservesEvidence(t *testing.T) {
	for _, body := range []string{`null`, `{"version":"3"}`, `{"bindings":{}}`, `{"bindings":[{"role":"roles/viewer","members":[42]}]}`, `{"version":1,"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":{"expression":"true"}}]}`, `{"version":3,"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":null}]}`} {
		c := secretIAMClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		a := secretIAMAsset("projects/123/secrets/secret")
		a.IAM = Object{"etag": "prior-evidence"}
		s := Snapshot{Assets: []Asset{a}}
		c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || s.Assets[0].IAM["etag"] != "prior-evidence" || s.Assets[0].Resource.Data["rotation"] == nil {
			t.Fatal(body, s)
		}
	}
}

func TestViewerSecretIAMPermissionAndServerDenialContinue(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		calls := 0
		c := secretIAMClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if strings.Contains(r.URL.Path, "/first:") {
				return response(403, "PRIVATE"), nil
			}
			return response(200, `{}`), nil
		})
		if !allowed {
			c.viewerPolicy.permissions = map[string]bool{}
		}
		s := Snapshot{Assets: []Asset{secretIAMAsset("projects/123/secrets/first"), secretIAMAsset("projects/123/secrets/second")}}
		c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || (!allowed && calls != 0) || (allowed && (calls != 2 || s.Assets[1].IAM == nil)) {
			t.Fatal(s, calls)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal(string(b))
		}
	}
}

func TestViewerSecretIAMRejectsMalformedIdentities(t *testing.T) {
	c := secretIAMClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network"); return nil, nil })
	for _, name := range []string{"projects/123/secrets/secret/versions/1", "projects/123/locations/global/secrets/secret", "projects/123/locations/evil.invalid/secrets/secret", "projects/123/secrets/secret:access", "projects/123/secrets/secret?alt=media"} {
		s := Snapshot{Assets: []Asset{secretIAMAsset(name)}}
		c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
	for _, regional := range []bool{false, true} {
		a := secretIAMAsset("projects/123/secrets/secret")
		if regional {
			a = secretIAMAsset("projects/123/locations/us-central1/secrets/secret")
			a.Resource.Location = "us-east1"
		} else {
			a.Resource.Data["name"] = "projects/999/secrets/secret"
		}
		s := Snapshot{Assets: []Asset{a}}
		c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}

func TestViewerSecretIAMDirectPolicySurvivesCAISearch(t *testing.T) {
	c := secretIAMClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "secretmanager.googleapis.com" {
			return response(200, `{}`), nil
		}
		return response(200, `{"results":[{"resource":"//secretmanager.googleapis.com/projects/123/secrets/secret","assetType":"secretmanager.googleapis.com/Secret","project":"projects/123","policy":{"bindings":[{"role":"roles/viewer","members":["allUsers"]}]}}]}`), nil
	})
	c.viewerPolicy.permissions["cloudasset.assets.searchAllIamPolicies"] = true
	s := Snapshot{Assets: []Asset{secretIAMAsset("projects/123/secrets/secret")}}
	c.CollectViewerSecretIAM(context.Background(), &s, "demo", "projects/123")
	c.viewerSearchIAM(context.Background(), &s, "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 1 || s.Assets[0].IAM == nil || len(s.Assets[0].IAM) != 0 {
		t.Fatal(s)
	}
}
