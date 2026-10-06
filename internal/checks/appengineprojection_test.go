package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestAppEngineProjectedSecretsValidation(t *testing.T) {
	digest := strings.Repeat("a", 64)
	a := asset("appengine.googleapis.com/Version", `{}`)
	a.Resource.Data["_gcpbusterSecretCandidates"] = []any{
		inventory.Object{"field": "envVariables", "name_digest": digest, "rule": "sensitive_variable_name", "value": "SENTINEL"},
		inventory.Object{"field": "envVariables", "name_digest": digest, "rule": "sensitive_variable_name"},
		inventory.Object{"field": "buildEnvVariables", "name_digest": digest, "rule": "private_key"},
		inventory.Object{"field": "SENTINEL", "name_digest": digest, "rule": "private_key"},
		inventory.Object{"field": "envVariables", "name_digest": "SENTINEL", "rule": "private_key"},
		inventory.Object{"field": "envVariables", "name_digest": digest, "rule": "SENTINEL"}, nil,
	}
	got := configurationSecrets(a, time.Now())
	if len(got) != 2 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENTINEL") {
		t.Fatal(string(b))
	}
	a.Type = "compute.googleapis.com/Instance"
	if got := configurationSecrets(a, time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestAppEngineProtectionServingStatusSanitized(t *testing.T) {
	a := asset("appengine.googleapis.com/Application", `{"iap":{"enabled":false},"servingStatus":"SENTINEL"}`)
	got := appEngineProtection(a, time.Now())
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SENTINEL") {
		t.Fatal(string(b))
	}
}
