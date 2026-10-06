package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceConfigPinsSafeEvidence(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/ServiceConfig", `{"producerProjectId":"demo","_gcpbusterGatewayPins":[{"apiConfig":"//apigateway.googleapis.com/projects/demo/locations/global/apis/api/configs/config","gateways":["//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway","https://NEVER_SAVE","//apigateway.googleapis.com/projects/foreign/locations/us-central1/gateways/gateway"],"secret":"NEVER_SAVE"},{"apiConfig":"NEVER_SAVE","gateways":[]}]}`)
	got := serviceConfigPinEvidence(a)
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "NEVER_SAVE") || strings.Contains(string(b), "foreign") {
		t.Fatal(string(b))
	}
}
