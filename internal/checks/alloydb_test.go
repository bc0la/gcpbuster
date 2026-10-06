package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAlloyDBPublicConfigurationExplicitOnly(t *testing.T) {
	for _, tc := range []struct {
		data  string
		want  int
		world bool
	}{
		{`{}`, 0, false}, {`{"networkConfig":{"enablePublicIp":"true"}}`, 0, false}, {`{"networkConfig":{"enableOutboundPublicIp":true},"ipAddress":"10.1.2.3"}`, 0, false},
		{`{"networkConfig":{"enablePublicIp":true,"authorizedExternalNetworks":[{"cidrRange":"0.0.0.0/0","description":"SENTINEL"}]},"publicIpAddress":"SENTINEL"}`, 1, true},
		{`{"publicIpAddress":"8.8.8.8","networkConfig":{"authorizedExternalNetworks":[{"cidrRange":"::/0"}]}}`, 1, true},
		{`{"networkConfig":{"enablePublicIp":false},"publicIpAddress":"8.8.8.8"}`, 0, false},
		{`{"publicIpAddress":"10.1.2.3"}`, 0, false},
		{`{"networkConfig":{"enablePublicIp":true,"authorizedExternalNetworks":[{"cidrRange":"10.0.0.0/8"},{"cidrRange":"SENTINEL"}]}}`, 1, false},
	} {
		got := alloyDBPublicConfiguration(asset("alloydb.googleapis.com/Instance", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 {
			_, world := got[0].Evidence["world_authorized_ranges"]
			if world != tc.world {
				t.Fatal(tc, got)
			}
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SENTINEL") {
			t.Fatal(string(b))
		}
	}
}
func TestAlloyDBClientProtectionExactEnums(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{}`, 0}, {`{"clientConnectionConfig":{"requireConnectors":false}}`, 1}, {`{"clientConnectionConfig":{"requireConnectors":"false"}}`, 0},
		{`{"clientConnectionConfig":{"sslConfig":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}`, 1},
		{`{"clientConnectionConfig":{"requireConnectors":false,"sslConfig":{"sslMode":"SSL_MODE_ALLOW"}}}`, 2},
		{`{"clientConnectionConfig":{"requireConnectors":true,"sslConfig":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}`, 0},
		{`{"clientConnectionConfig":{"sslConfig":{"sslMode":"SSL_MODE_UNSPECIFIED"}}}`, 0},
		{`{"clientConnectionConfig":{"sslConfig":{"sslMode":"ENCRYPTED_ONLY"}}}`, 0},
		{`{"clientConnectionConfig":{"sslConfig":{"sslMode":"SSL_MODE_REQUIRE"}}}`, 0},
		{`{"clientConnectionConfig":{"sslConfig":{"sslMode":"SSL_MODE_VERIFY_CA"}}}`, 0},
	} {
		if got := alloyDBClientProtection(asset("alloydb.googleapis.com/Instance", tc.data), time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestAlloyDBDataAPIExplicitAuthorizationBoundary(t *testing.T) {
	for _, mode := range []string{"", "ENABLED", "DISABLED", "DEFAULT_DATA_API_ENABLED_FOR_GOOGLE_CLOUD_SERVICES", "SENTINEL"} {
		want := 0
		if mode == "ENABLED" {
			want = 1
		}
		got := alloyDBDataAPI(asset("alloydb.googleapis.com/Instance", `{"dataApiAccess":"`+mode+`","databaseRoles":["SENTINEL"]}`), time.Now())
		if len(got) != want {
			t.Fatal(mode, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SENTINEL") {
			t.Fatal(string(b))
		}
	}
}
