package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func keyMetadataClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Collector fixtures are not proof of predefined-role membership.
	c.viewerPolicy.permissions = map[string]bool{"secretmanager.secrets.list": true, "secretmanager.versions.list": true, "cloudkms.locations.list": true, "cloudkms.keyRings.list": true, "cloudkms.cryptoKeys.list": true, "cloudkms.cryptoKeyVersions.list": true, "cloudkms.keyRings.getIamPolicy": true, "cloudkms.cryptoKeys.getIamPolicy": true}
	return c
}

func TestViewerKeyMetadataTreeAndLifecycle(t *testing.T) {
	seen := map[string]int{}
	c := keyMetadataClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || (strings.Contains(r.URL.Path, ":") && !strings.HasSuffix(r.URL.Path, ":getIamPolicy")) {
			t.Fatal("nonmetadata method", r.URL)
		}
		key := r.URL.Host + r.URL.Path
		seen[key]++
		switch key {
		case "cloudkms.googleapis.com/v1/projects/demo/locations/us-central1/keyRings/ring:getIamPolicy", "cloudkms.googleapis.com/v1/projects/demo/locations/us-central1/keyRings/ring/cryptoKeys/key:getIamPolicy":
			if r.URL.Query().Get("options.requestedPolicyVersion") != "3" {
				t.Fatal("policy version missing")
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/cloudkms.cryptoKeyDecrypter","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')","title":"expires"}}]}`), nil
		case "secretmanager.googleapis.com/v1/projects/123/secrets":
			return response(200, `{"secrets":[{"name":"projects/123/secrets/secret","rotation":{"nextRotationTime":"2020-01-01T00:00:00Z"},"versionDestroyTtl":"86400s"}]}`), nil
		case "secretmanager.googleapis.com/v1/projects/123/secrets/secret/versions":
			return response(200, `{"versions":[{"name":"projects/123/secrets/secret/versions/1","state":"DISABLED","scheduledDestroyTime":"2030-01-01T00:00:00Z"}]}`), nil
		case "cloudkms.googleapis.com/v1/projects/demo/locations":
			if r.URL.Query().Get("pageToken") == "next" {
				return response(200, `{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}]}`), nil
			}
			return response(200, `{"locations":[],"nextPageToken":"next"}`), nil
		case "cloudkms.googleapis.com/v1/projects/demo/locations/us-central1/keyRings":
			return response(200, `{"keyRings":[{"name":"projects/demo/locations/us-central1/keyRings/ring"}]}`), nil
		case "cloudkms.googleapis.com/v1/projects/demo/locations/us-central1/keyRings/ring/cryptoKeys":
			return response(200, `{"cryptoKeys":[{"name":"projects/demo/locations/us-central1/keyRings/ring/cryptoKeys/key","purpose":"ENCRYPT_DECRYPT","versionTemplate":{"protectionLevel":"SOFTWARE"},"nextRotationTime":"2020-01-01T00:00:00Z"}]}`), nil
		case "cloudkms.googleapis.com/v1/projects/demo/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions":
			return response(200, `{"cryptoKeyVersions":[{"name":"projects/demo/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1","state":"DESTROY_SCHEDULED","destroyTime":"2030-01-01T00:00:00Z"}]}`), nil
		default:
			t.Fatal("unexpected endpoint", key)
			return nil, nil
		}
	})
	var s Snapshot
	c.CollectViewerKeyMetadata(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 5 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if s.Assets[1].Type != "secretmanager.googleapis.com/SecretVersion" || Str(s.Assets[1].Resource.Data["state"]) != "DISABLED" || s.Assets[4].Type != "cloudkms.googleapis.com/CryptoKeyVersion" || Str(s.Assets[4].Resource.Data["destroyTime"]) == "" {
		t.Fatal(s.Assets)
	}
	for _, i := range []int{2, 3} {
		if s.Assets[i].IAM["version"] != float64(3) || Str(Get(Obj(List(s.Assets[i].IAM["bindings"])[0]), "condition", "expression")) == "" {
			t.Fatal("conditional IAM missing", s.Assets[i])
		}
	}
}

func TestViewerKeyMetadataRejectsForeignAndPayloadResources(t *testing.T) {
	for _, body := range []string{`{"secrets":[{"name":"projects/999/secrets/other"}]}`, `{"secrets":[{"name":"projects/123/secrets/nested/versions/1"}]}`, `{"secrets":[{"name":"projects/123/secrets/secret","payload":{"data":"PRIVATE"}}]}`, `{"secrets":{}}`, `{"secrets":[null]}`, `{"nextPageToken":3}`} {
		c := keyMetadataClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		rows := c.viewerKeyChildren(context.Background(), &s, "secretmanager.googleapis.com", "projects/123", "secrets", "Secret", "projects/123", "demo", false)
		if len(rows) != 0 || len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(body, s)
		}
	}
}

func TestViewerKeyMetadataKeepsPartialAndContinuesChildren(t *testing.T) {
	versions := 0
	c := keyMetadataClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "cloudkms.googleapis.com" {
			return response(200, `{}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/versions") {
			versions++
			return response(200, `{}`), nil
		}
		if r.URL.Query().Get("pageToken") == "next" {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{"secrets":[{"name":"projects/123/secrets/good"}],"nextPageToken":"next"}`), nil
	})
	var s Snapshot
	c.CollectViewerKeyMetadata(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || versions != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s, versions)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("error body leaked")
	}
}

func TestViewerKeyMetadataUnreachableKeepsLaterPages(t *testing.T) {
	calls := 0
	c := keyMetadataClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"secrets":[{"name":"projects/123/secrets/one"}],"unreachable":["us-east1"],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"secrets":[{"name":"projects/123/secrets/two"}]}`), nil
	})
	s := Snapshot{}
	rows := c.viewerKeyChildren(context.Background(), &s, "secretmanager.googleapis.com", "projects/123", "secrets", "Secret", "projects/123", "demo", false)
	if calls != 2 || len(rows) != 2 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
}

func TestViewerKeyMetadataMissingPermissionAndInvalidProject(t *testing.T) {
	c := keyMetadataClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network called"); return nil, nil })
	var s Snapshot
	c.CollectViewerKeyMetadata(context.Background(), &s, "../escape", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c.viewerPolicy.permissions = map[string]bool{}
	s = Snapshot{}
	c.CollectViewerKeyMetadata(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
		t.Fatal(s)
	}
}

func TestViewerKeyIAMDeniedRetainsLifecycleMetadata(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		t.Run(map[bool]string{false: "baseline-denied", true: "server-denied"}[authorized], func(t *testing.T) {
			policyCalls := 0
			c := keyMetadataClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
					policyCalls++
					return response(403, "PRIVATE_ERROR"), nil
				}
				return response(200, `{"cryptoKeys":[{"name":"projects/demo/locations/global/keyRings/ring/cryptoKeys/key","purpose":"ENCRYPT_DECRYPT"}]}`), nil
			})
			if !authorized {
				delete(c.viewerPolicy.permissions, "cloudkms.cryptoKeys.getIamPolicy")
			}
			s := Snapshot{}
			rows := c.viewerKeyChildren(context.Background(), &s, "cloudkms.googleapis.com", "projects/demo/locations/global/keyRings/ring", "cryptoKeys", "CryptoKey", "projects/123", "demo", false)
			if len(rows) != 1 || len(s.Assets) != 1 || s.Assets[0].IAM != nil || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
			if (authorized && policyCalls != 1) || (!authorized && policyCalls != 0) {
				t.Fatal("guard did not stop transport", policyCalls)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "PRIVATE_ERROR") {
				t.Fatal(string(b))
			}
		})
	}
}

func TestViewerKeyIAMMalformedPolicies(t *testing.T) {
	for _, body := range []string{
		`null`, `{"version":"3"}`, `{"version":2}`, `{"bindings":{}}`,
		`{"bindings":[{"role":"bad","members":["allUsers"]}]}`,
		`{"bindings":[{"role":"roles/viewer","members":[]}]}`,
		`{"bindings":[{"role":"roles/viewer","members":[42]}]}`,
		`{"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":{"expression":"true"}}]}`,
		`{"version":3,"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":null}]}`,
		`{"version":3,"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":{"expression":" "}}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := keyMetadataClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
			a := NewAsset("//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring", "cloudkms.googleapis.com/KeyRing", nil)
			s := Snapshot{}
			c.viewerKeyIAM(context.Background(), &s, &a, "demo")
			if a.IAM != nil || !hasCoverage(s, "failed") {
				t.Fatal(s, a)
			}
		})
	}
}

func TestViewerKeyIAMEmptyDirectPolicySurvivesSearch(t *testing.T) {
	c := keyMetadataClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "cloudkms.googleapis.com" {
			return response(200, `{}`), nil
		}
		return response(200, `{"results":[{"resource":"//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring","assetType":"cloudkms.googleapis.com/KeyRing","project":"projects/123","policy":{"bindings":[{"role":"roles/viewer","members":["allUsers"]}]}}]}`), nil
	})
	c.viewerPolicy.permissions["cloudasset.assets.searchAllIamPolicies"] = true
	a := NewAsset("//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring", "cloudkms.googleapis.com/KeyRing", nil)
	s := Snapshot{}
	c.viewerKeyIAM(context.Background(), &s, &a, "demo")
	s.Assets = append(s.Assets, a)
	c.viewerSearchIAM(context.Background(), &s, "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 1 || s.Assets[0].IAM == nil || len(s.Assets[0].IAM) != 0 {
		t.Fatal(s)
	}
}

func TestViewerKeyIAMRejectsUnexpectedScopeOrKind(t *testing.T) {
	c := keyMetadataClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network"); return nil, nil })
	for _, name := range []string{
		"//cloudkms.googleapis.com/projects/other/locations/global/keyRings/ring",
		"//evil.invalid/projects/demo/locations/global/keyRings/ring",
		"//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring:decrypt",
		"//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
	} {
		a := NewAsset(name, "cloudkms.googleapis.com/KeyRing", nil)
		s := Snapshot{}
		c.viewerKeyIAM(context.Background(), &s, &a, "demo")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}
