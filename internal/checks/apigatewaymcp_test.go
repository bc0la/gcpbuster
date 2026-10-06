package checks

import (
	"testing"
	"time"
)

func TestAPIGatewayMCPDiscoveryExplicitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		state, mcp string
		want       int
	}{
		{"ACTIVE", `{"complete":true,"enabled":true,"eligible_declared_tools":1,"tools_list_auth":"none"}`, 1},
		{"ACTIVE", `{"complete":true,"enabled":true,"eligible_declared_tools":0,"tools_list_auth":"none"}`, 0},
		{"ACTIVE", `{"complete":true,"enabled":true,"tools_list_auth":"none"}`, 0},
		{"CREATING", `{"complete":true,"enabled":true,"tools_list_auth":"none"}`, 0},
		{"ACTIVE", `{"complete":false,"enabled":true,"tools_list_auth":"none"}`, 0},
		{"ACTIVE", `{"enabled":true,"tools_list_auth":"none"}`, 0},
		{"ACTIVE", `{"complete":true,"enabled":"true","tools_list_auth":"none"}`, 0},
		{"ACTIVE", `{"complete":true,"enabled":true,"tools_list_auth":"jwt"}`, 0},
		{"ACTIVE", `{"complete":true,"enabled":true,"tools_list_auth":"api_key"}`, 0},
		{"ACTIVE", `{"complete":true,"enabled":false,"tools_list_auth":"disabled"}`, 0},
	} {
		a := asset("apigateway.googleapis.com/ApiConfig", `{"state":"`+tc.state+`","_gcpbusterAuth":{"version":"3.0.3","mcp":`+tc.mcp+`}}`)
		got := apiGatewayMCPDiscovery(a, time.Time{})
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestAPIGatewayMCPDiscoveryRequiresSupportedVersion(t *testing.T) {
	for _, version := range []string{"", "2.0", "3.2.0", "3.0.bad"} {
		a := asset("apigateway.googleapis.com/ApiConfig", `{"state":"ACTIVE","_gcpbusterAuth":{"version":"`+version+`","mcp":{"complete":true,"enabled":true,"eligible_declared_tools":1,"tools_list_auth":"none"}}}`)
		if got := apiGatewayMCPDiscovery(a, time.Time{}); len(got) != 0 {
			t.Fatal(version, got)
		}
	}
}
