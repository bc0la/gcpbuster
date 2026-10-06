package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAPIGatewayAuthConfiguredOperations(t *testing.T) {
	for _, mode := range []string{"none", "optional"} {
		a := asset("apigateway.googleapis.com/ApiConfig", `{"state":"ACTIVE","_gcpbusterAuth":{"version":"2.0","complete":false,"routes":[{"method":"GET","route_digest":"`+strings.Repeat("a", 64)+`","auth":"`+mode+`","security_source":"operation","description":"SOURCE_SENTINEL"}]}}`)
		got := apiGatewayAuth(a, time.Time{})
		if len(got) != 1 {
			t.Fatal(got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SOURCE_SENTINEL") || !strings.Contains(string(b), "not verified deployment") {
			t.Fatal("unsafe evidence")
		}
	}
}

func TestAPIGatewayAuthUnknownNotAnonymous(t *testing.T) {
	baseline := `{"state":"ACTIVE","_gcpbusterAuth":{"version":"2.0","routes":[{"method":"GET","route_digest":"` + strings.Repeat("a", 64) + `","auth":"none","security_source":"root"}]}}`
	for _, pair := range [][2]string{{`"ACTIVE"`, `"CREATING"`}, {`"2.0"`, `"3.2.0"`}, {`"none"`, `"api_key"`}, {`"none"`, `"jwt"`}, {`"none"`, `"mixed"`}, {`"none"`, `null`}, {`"GET"`, `"SOURCE_SENTINEL"`}, {`"root"`, `"SOURCE_SENTINEL"`}, {strings.Repeat("a", 64), "SOURCE_SENTINEL"}} {
		data := strings.ReplaceAll(baseline, pair[0], pair[1])
		if got := apiGatewayAuth(asset("apigateway.googleapis.com/ApiConfig", data), time.Time{}); len(got) != 0 {
			t.Fatal(pair, got)
		}
	}
	if got := apiGatewayAuth(asset("apigateway.googleapis.com/Gateway", baseline), time.Time{}); len(got) != 0 {
		t.Fatal(got)
	}
	if got := apiGatewayAuth(asset("apigateway.googleapis.com/ApiConfig", `{"state":"ACTIVE","defaultHostname":"example"}`), time.Time{}); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestAPIGatewayAuthOpenAPI3ConfiguredOperations(t *testing.T) {
	for _, version := range []string{"3.0.3", "3.1.0"} {
		a := asset("apigateway.googleapis.com/ApiConfig", `{"state":"ACTIVE","_gcpbusterAuth":{"version":"`+version+`","complete":false,"routes":[{"method":"TRACE","route_digest":"`+strings.Repeat("a", 64)+`","auth":"none","security_source":"implicit"}]}}`)
		if got := apiGatewayAuth(a, time.Time{}); len(got) != 1 {
			t.Fatal(got)
		}
	}
}
