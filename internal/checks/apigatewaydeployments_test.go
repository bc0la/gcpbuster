package checks

import (
	"testing"
)

func TestAPIGatewayDeploymentEvidenceProjection(t *testing.T) {
	a := asset("apigateway.googleapis.com/ApiConfig", `{"_gcpbusterGateways":["//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway","//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway","https://credential@example.test",{"secret":"NEVER_SAVE"},"//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway?secret=value"]}`)
	if got := apiGatewayDeploymentEvidence(a); len(got) != 1 {
		t.Fatal(got)
	}
}
