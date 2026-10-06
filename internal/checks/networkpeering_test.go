package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNetworkPeeringExplicitCustomRoutes(t *testing.T) {
	a := asset("compute.googleapis.com/Network", `{"peerings":[{"name":"peer","network":"https://www.googleapis.com/compute/v1/projects/other-project/global/networks/peer-net","state":"ACTIVE","exportCustomRoutes":true,"importCustomRoutes":false,"stateDetails":"SECRET_SENTINEL","connectionStatus":{"trafficConfiguration":{"exportCustomRoutesToPeer":false}}}]}`)
	got := networkPeeringRoutes(a, time.Time{})
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["peer_network"] != "projects/other-project/global/networks/peer-net" {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SECRET_SENTINEL") || !strings.Contains(string(raw), "not established") {
		t.Fatal(string(raw))
	}
}

func TestNetworkPeeringUnknownIsNotExchange(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"peerings":false}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n","state":"INACTIVE","exportCustomRoutes":true}]}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n","exportCustomRoutes":true}]}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n","state":"ACTIVE","exportCustomRoutes":"true"}]}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n","state":"ACTIVE","exportCustomRoutes":false}]}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n","state":"ACTIVE","connectionStatus":{"trafficConfiguration":{"exportCustomRoutesToPeer":true}}}]}`,
		`{"peerings":[{"name":"peer","network":"https://user:secret@example.test/x","state":"ACTIVE","exportCustomRoutes":true}]}`,
		`{"peerings":[{"name":"peer","network":"global/networks/n","state":"ACTIVE","exportCustomRoutes":true}]}`,
		`{"peerings":[{"name":"peer","network":"https://www.googleapis.com/compute/v1/https://compute.googleapis.com/compute/v1/projects/p/global/networks/n","state":"ACTIVE","exportCustomRoutes":true}]}`,
		`{"peerings":[{"name":"peer","network":"projects/p/global/networks/n?secret=value","state":"ACTIVE","exportCustomRoutes":true}]}`,
	} {
		if got := networkPeeringRoutes(asset("compute.googleapis.com/Network", data), time.Time{}); len(got) != 0 {
			t.Fatal(data, got)
		}
	}
}
