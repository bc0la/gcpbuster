package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAPIGatewaySecretCandidatesOnly(t *testing.T) {
	a := asset("apigateway.googleapis.com/ApiConfig", `{"_gcpbusterSecretCandidates":[{"documentIndex":0,"line":2,"rule":"credential_assignment","secret":"DO_NOT_PERSIST"},{"documentIndex":-1,"line":2,"rule":"github_token"},{"documentIndex":0,"line":0,"rule":"github_token"},{"documentIndex":0,"line":2,"rule":"DO_NOT_PERSIST"}]}`)
	got := apiGatewaySecrets(a, time.Time{})
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "DO_NOT_PERSIST") {
		t.Fatal(string(b))
	}
	a.Type = "apigateway.googleapis.com/Gateway"
	if len(apiGatewaySecrets(a, time.Time{})) != 0 {
		t.Fatal("wrong resource")
	}
}
