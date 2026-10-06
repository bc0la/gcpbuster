package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemorystoreAuthenticationExplicitOnly(t *testing.T) {
	for _, tc := range []struct {
		kind, data string
		want       int
	}{
		{"Instance", `{"authEnabled":false,"authString":"SENTINEL","host":"SENTINEL"}`, 1},
		{"Instance", `{}`, 0}, {"Instance", `{"authEnabled":"false"}`, 0}, {"Instance", `{"authEnabled":true}`, 0}, {"Instance", `{"authorizationMode":"AUTH_MODE_DISABLED"}`, 0},
		{"Cluster", `{"authorizationMode":"AUTH_MODE_DISABLED","discoveryEndpoints":[{"address":"SENTINEL"}]}`, 1},
		{"Cluster", `{}`, 0}, {"Cluster", `{"authorizationMode":"AUTH_MODE_UNSPECIFIED"}`, 0}, {"Cluster", `{"authorizationMode":"AUTH_MODE_IAM_AUTH"}`, 0}, {"Cluster", `{"authorizationMode":"AUTH_MODE_TOKEN_AUTH"}`, 0}, {"Cluster", `{"authorizationMode":false}`, 0}, {"Cluster", `{"authEnabled":false}`, 0},
	} {
		got := memorystoreAuthentication(asset("redis.googleapis.com/"+tc.kind, tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SENTINEL") {
			t.Fatal(string(b))
		}
	}
	if got := memorystoreAuthentication(asset("memcache.googleapis.com/Instance", `{"authEnabled":false}`), time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}
func TestMemorystoreTransportProductEnums(t *testing.T) {
	for _, kind := range []string{"Instance", "Cluster"} {
		for _, mode := range []string{"", "DISABLED", "SERVER_AUTHENTICATION", "TRANSIT_ENCRYPTION_MODE_DISABLED", "TRANSIT_ENCRYPTION_MODE_SERVER_AUTHENTICATION", "TRANSIT_ENCRYPTION_MODE_UNSPECIFIED", "SENTINEL"} {
			want := 0
			if kind == "Instance" && mode == "DISABLED" || kind == "Cluster" && mode == "TRANSIT_ENCRYPTION_MODE_DISABLED" {
				want = 1
			}
			got := memorystoreTransport(asset("redis.googleapis.com/"+kind, `{"transitEncryptionMode":"`+mode+`","serverCaCerts":["SENTINEL"]}`), time.Now())
			if len(got) != want {
				t.Fatal(kind, mode, got)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "SENTINEL") {
				t.Fatal(string(b))
			}
		}
	}
	for _, data := range []string{`{}`, `{"transitEncryptionMode":false}`, `{"transitEncryptionMode":null}`} {
		if got := memorystoreTransport(asset("redis.googleapis.com/Instance", data), time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
