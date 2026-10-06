package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func computeDiskClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"compute.images.list": true, "compute.snapshots.list": true, "compute.regions.list": true, "compute.images.getIamPolicy": true, "compute.snapshots.getIamPolicy": true}
	return c
}

func TestViewerComputeDisksPaginationProjectionRegionalIAM(t *testing.T) {
	calls := map[string]int{}
	c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "compute.googleapis.com" {
			t.Fatal(r.Method, r.URL)
		}
		calls[r.URL.Path]++
		path := strings.TrimPrefix(r.URL.Path, "/compute/v1/projects/demo/")
		if strings.HasSuffix(path, "/getIamPolicy") {
			if r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" {
				t.Fatal(r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/compute.imageUser","members":["allUsers"],"condition":{"expression":"false","unknown":"DO_NOT_KEEP"},"unknown":"DO_NOT_KEEP"}],"_gcpbusterBindingsOnly":true,"unknown":"DO_NOT_KEEP"}`), nil
		}
		switch path {
		case "global/images":
			if r.URL.Query().Get("fields") != viewerComputeImageFields {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"items":[{"name":"image","selfLink":"https://www.googleapis.com/compute/v1/projects/123/global/images/image","imageEncryptionKey":{"kmsKeyName":"projects/demo/locations/global/keyRings/r/cryptoKeys/k","rawKey":"DO_NOT_KEEP","sha256":"DO_NOT_KEEP"},"deprecated":{"state":"DEPRECATED","replacement":"projects/demo/global/images/replacement","unknown":"DO_NOT_KEEP"},"rawDisk":{"source":"DO_NOT_KEEP"},"labels":{"x":"DO_NOT_KEEP"},"licenses":["DO_NOT_KEEP"]}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"items":[{"name":"image"},{"name":"second"}]}`), nil
		case "global/snapshots":
			return response(200, `{"items":[{"name":"snapshot","snapshotType":"STANDARD","status":"READY","snapshotEncryptionKey":{"kmsKeyServiceAccount":"sa@example.com","rsaEncryptedKey":"DO_NOT_KEEP"}}]}`), nil
		case "regions":
			if calls[r.URL.Path] == 1 {
				return response(200, `{"items":[{"name":"us-central1"}],"nextPageToken":"regions"}`), nil
			}
			return response(200, `{"items":[{"name":"us-central1"}]}`), nil
		case "regions/us-central1/snapshots":
			return response(200, `{"items":[{"name":"regional","selfLink":"https://compute.googleapis.com/compute/v1/projects/demo/regions/us-central1/snapshots/regional","storageLocations":["us-central1"]}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerComputeDisks(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 4 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if s.Assets[3].Name != "//compute.googleapis.com/projects/demo/regions/us-central1/snapshots/regional" || s.Assets[3].Resource.Location != "us-central1" {
		t.Fatal(s.Assets[3])
	}
	for _, a := range s.Assets {
		if a.IAM == nil {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") || strings.Contains(string(b), "_gcpbusterBindingsOnly") {
		t.Fatal(string(b))
	}
}

func TestViewerComputeDisksMalformedMetadataRetainsValid(t *testing.T) {
	c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/getIamPolicy") {
			return response(200, `{}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/images") {
			return response(200, `{"items":[null,{"name":"../bad"},{"name":"foreign","selfLink":"https://compute.googleapis.com/compute/v1/projects/other/global/images/foreign"},{"name":"badkey","imageEncryptionKey":false},{"name":"badtime","creationTimestamp":"bad"},{"name":"badstorage","storageLocations":[false]},{"name":"valid"}]}`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerComputeDisks(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") || s.Assets[0].IAM == nil {
		t.Fatal(s)
	}
}

func TestViewerComputeDiskPolicyDenialAndLatePagePreserveMetadata(t *testing.T) {
	for _, mode := range []string{"permission", "server", "malformed-policy", "late-list"} {
		t.Run(mode, func(t *testing.T) {
			c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/getIamPolicy") {
					if mode == "permission" {
						t.Fatal("unauthorized policy call")
					}
					if mode == "server" {
						return response(403, `{}`), nil
					}
					if mode == "malformed-policy" {
						return response(200, `{"version":1,"bindings":[{"role":"roles/viewer","members":["allUsers"],"condition":{"expression":"true"}}]}`), nil
					}
					return response(200, `{}`), nil
				}
				if strings.HasSuffix(r.URL.Path, "/images") {
					if r.URL.Query().Get("pageToken") != "" {
						return response(403, `{}`), nil
					}
					next := ""
					if mode == "late-list" {
						next = `,"nextPageToken":"next"`
					}
					return response(200, `{"items":[{"name":"retained"}]`+next+`}`), nil
				}
				return response(200, `{}`), nil
			})
			if mode == "permission" {
				delete(c.viewerPolicy.permissions, "compute.images.getIamPolicy")
			}
			s := Snapshot{}
			c.CollectViewerComputeDisks(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
			if mode != "late-list" && s.Assets[0].IAM != nil {
				t.Fatal("invented policy", s)
			}
		})
	}
}

func TestViewerComputeDiskRegionsPartialStillCollects(t *testing.T) {
	calls := 0
	c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/regions") {
			calls++
			if calls == 1 {
				return response(200, `{"items":[{"name":"us-central1"},{"name":"foreign","selfLink":"https://evil.invalid"}],"warning":{"code":"UNREACHABLE"},"nextPageToken":"next"}`), nil
			}
			return response(403, `{}`), nil
		}
		if strings.Contains(r.URL.Path, "/regions/us-central1/") && !strings.HasSuffix(r.URL.Path, "getIamPolicy") {
			return response(200, `{"items":[{"name":"regional"}]}`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerComputeDisks(context.Background(), &s, "demo", "projects/123")
	if calls != 2 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
}

func TestViewerComputeDiskInvalidScopeNoTransport(t *testing.T) {
	c := computeDiskClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerComputeDisks(context.Background(), &s, "demo/global/x", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
