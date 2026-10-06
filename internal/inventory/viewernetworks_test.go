package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func networkClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	c.viewerPolicy.permissions = map[string]bool{"compute.networks.list": true, "compute.subnetworks.list": true, "compute.subnetworks.getIamPolicy": true}
	return c
}

func TestViewerNetworksPaginationAliasesProjectionIAM(t *testing.T) {
	calls := map[string]int{}
	c := networkClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "compute.googleapis.com" {
			t.Fatal(r.URL)
		}
		calls[r.URL.Path]++
		switch strings.TrimPrefix(r.URL.Path, "/compute/v1/projects/demo/") {
		case "global/networks":
			if r.URL.Query().Get("fields") != viewerNetworkFields {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"items":[{"name":"vpc","selfLink":"https://www.googleapis.com/compute/v1/projects/123/global/networks/vpc","autoCreateSubnetworks":true,"networkFirewallPolicyEnforcementOrder":"BEFORE_CLASSIC_FIREWALL","routingConfig":{"routingMode":"GLOBAL","unknown":"DO_NOT_KEEP"},"peerings":[{"name":"peer","network":"https://compute.googleapis.com/compute/v1/projects/other/global/networks/remote","state":"ACTIVE","exportCustomRoutes":true,"connectionStatus":{"consensusState":"DO_NOT_KEEP","trafficConfiguration":{"exportCustomRoutesToPeer":true,"stackType":"IPV4_ONLY","unknown":"DO_NOT_KEEP"}},"stateDetails":"DO_NOT_KEEP"}],"description":"DO_NOT_KEEP"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal(r.URL)
			}
			return response(200, `{"items":[{"name":"vpc"}]}`), nil
		case "aggregated/subnetworks":
			if r.URL.Query().Get("fields") != viewerSubnetworkFields || r.URL.Query().Get("returnPartialSuccess") != "true" {
				t.Fatal(r.URL)
			}
			if calls[r.URL.Path] == 1 {
				return response(200, `{"items":{"regions/us-central1":{"subnetworks":[{"name":"subnet","selfLink":"https://compute.googleapis.com/compute/v1/projects/123/regions/us-central1/subnetworks/subnet","region":"https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1","network":"projects/demo/global/networks/vpc","privateIpGoogleAccess":false,"purpose":"PRIVATE","logConfig":{"enable":false,"flowSampling":0.5,"filterExpr":"DO_NOT_KEEP","metadataFields":["DO_NOT_KEEP"]}}]}},"nextPageToken":"next"}`), nil
			}
			return response(200, `{"items":{"regions/us-central1":{"subnetworks":[{"name":"subnet"}]},"regions/us-east1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}}}`), nil
		case "regions/us-central1/subnetworks/subnet/getIamPolicy":
			if r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" {
				t.Fatal(r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/compute.networkUser","members":["allAuthenticatedUsers"],"condition":{"expression":"false","unknown":"DO_NOT_KEEP"}}],"_gcpbusterBindingsOnly":true}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerNetworks(context.Background(), &s, "demo", "projects/123")
	if len(s.Assets) != 2 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	if s.Assets[1].Name != "//compute.googleapis.com/projects/demo/regions/us-central1/subnetworks/subnet" || s.Assets[1].IAM == nil {
		t.Fatal(s.Assets[1])
	}
	peer := Obj(List(s.Assets[0].Resource.Data["peerings"])[0])
	if Get(peer, "connectionStatus", "trafficConfiguration", "exportCustomRoutesToPeer") != true {
		t.Fatal(peer)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") || strings.Contains(string(b), "_gcpbusterBindingsOnly") {
		t.Fatal(string(b))
	}
}

func TestViewerNetworksMalformedScopeRowsAndPartialPages(t *testing.T) {
	count := 0
	c := networkClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/getIamPolicy") {
			return response(200, `{}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/networks") {
			return response(200, `{"items":[{"name":"bad","autoCreateSubnetworks":"true"},{"name":"valid"}]}`), nil
		}
		count++
		if count == 1 {
			return response(200, `{"items":{"zones/us-central1-a":{"subnetworks":[{"name":"wrongscope"}]},"regions/us-central1":{"subnetworks":[null,{"name":"foreign","selfLink":"https://compute.googleapis.com/compute/v1/projects/other/regions/us-central1/subnetworks/foreign"},{"name":"badlog","logConfig":{"flowSampling":2}},{"name":"valid"}]},"regions/us-east1":{"warning":{"code":"UNREACHABLE"}}},"nextPageToken":"next"}`), nil
		}
		return response(200, `{"items":{"regions/us-west1":{"subnetworks":[{"name":"last"}]}}}`), nil
	})
	s := Snapshot{}
	c.CollectViewerNetworks(context.Background(), &s, "demo", "projects/123")
	if count != 2 || len(s.Assets) != 3 || !hasCoverage(s, "failed") {
		t.Fatal(count, s)
	}
}

func TestViewerNetworksPolicyDenialAndLatePageRetainMetadata(t *testing.T) {
	for _, mode := range []string{"permission", "server", "malformed", "late"} {
		t.Run(mode, func(t *testing.T) {
			c := networkClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/getIamPolicy") {
					if mode == "permission" {
						t.Fatal("unauthorized transport")
					}
					if mode == "server" {
						return response(403, `{}`), nil
					}
					if mode == "malformed" {
						return response(200, `{"bindings":[{"role":"roles/compute.networkUser","members":["allUsers"],"condition":{"expression":"true"}}]}`), nil
					}
					return response(200, `{}`), nil
				}
				if strings.HasSuffix(r.URL.Path, "/networks") {
					return response(200, `{}`), nil
				}
				if r.URL.Query().Get("pageToken") != "" {
					return response(403, `{}`), nil
				}
				next := ""
				if mode == "late" {
					next = `,"nextPageToken":"next"`
				}
				return response(200, `{"items":{"regions/us-central1":{"subnetworks":[{"name":"subnet"}]}}`+next+`}`), nil
			})
			if mode == "permission" {
				delete(c.viewerPolicy.permissions, "compute.subnetworks.getIamPolicy")
			}
			s := Snapshot{}
			c.CollectViewerNetworks(context.Background(), &s, "demo", "projects/123")
			if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerNetworkRejectsInvalidIdentityAndPeering(t *testing.T) {
	for _, d := range []Object{{"name": "vpc", "peerings": []any{Object{"name": "peer", "network": "https://evil.invalid", "state": "ACTIVE"}}}, {"name": "vpc", "peerings": []any{Object{"name": "peer", "network": "projects/demo/global/networks/remote", "connectionStatus": Object{"trafficConfiguration": Object{"importCustomRoutesFromPeer": "true"}}}}}} {
		if _, err := viewerNetworkAsset(d, "demo", "projects/123", "global", "networks", "Network"); err == nil {
			t.Fatal(d)
		}
	}
	c := networkClient(t, func(r *http.Request) (*http.Response, error) { t.Fatal(r.URL); return nil, nil })
	s := Snapshot{}
	c.CollectViewerNetworks(context.Background(), &s, "../other", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerNetworkSameProjectPeeringReference(t *testing.T) {
	for _, tc := range []struct {
		ref   string
		valid bool
	}{
		{"global/networks/remote", true},
		{"global/networks/remote?x=y", false},
		{"global/networks/../remote", false},
		{"global/networks/remote/extra", false},
		{"global/networks/", false},
		{"remote", false},
		{"/global/networks/remote", false},
		{"https://evil.invalid/global/networks/remote", false},
	} {
		d := Object{"name": "vpc", "peerings": []any{Object{"name": "peer", "network": tc.ref, "state": "ACTIVE", "exportCustomRoutes": true}}}
		a, err := viewerNetworkAsset(d, "demo", "projects/123", "global", "networks", "Network")
		if (err == nil) != tc.valid {
			t.Fatal(tc, err)
		}
		if tc.valid && Str(Obj(List(a.Resource.Data["peerings"])[0])["network"]) != "projects/demo/global/networks/remote" {
			t.Fatal(a)
		}
	}
}
