package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func paritySecretAsset(shape, name, value string) inventory.Asset {
	var data inventory.Object
	kind := "run.googleapis.com/Service"
	switch shape {
	case "run_env":
		data = inventory.Object{"template": inventory.Object{"containers": []any{inventory.Object{"env": []any{inventory.Object{"name": name, "value": value}}}}}}
	case "function_map":
		kind = "cloudfunctions.googleapis.com/Function"
		data = inventory.Object{"serviceConfig": inventory.Object{"environmentVariables": inventory.Object{name: value}}}
	case "compute_metadata":
		kind = "compute.googleapis.com/Instance"
		data = inventory.Object{"metadata": inventory.Object{"items": []any{inventory.Object{"key": name, "value": value}}}}
	}
	return inventory.NewAsset("fixture", kind, data)
}

func assertParitySecretRedacted(t *testing.T, a inventory.Asset, value string, want int) {
	t.Helper()
	got := configurationSecrets(a, time.Time{})
	if len(got) != want {
		t.Fatalf("findings=%d want=%d: %+v", len(got), want, got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if want > 0 {
		if !strings.Contains(string(encoded), "[REDACTED]") || strings.Contains(string(encoded), value) {
			t.Fatal("candidate value leaked or unredacted")
		}
		for _, r := range got {
			if r.Severity != "high" {
				t.Fatal("changed source candidate severity", r)
			}
		}
	}
}

func TestConfigurationSecretsLambdaNameParity(t *testing.T) {
	for _, shape := range []string{"run_env", "function_map", "compute_metadata"} {
		for _, name := range []string{"SECRET", "TOKEN", "ID_TOKEN", "PASSWORD", "PASSWD", "API_KEY", "API-KEY", "APIKEY", "ACCESS_KEY", "ACCESS-KEY", "ACCESSKEY", "PRIVATE_KEY", "PRIVATE-KEY", "PRIVATEKEY", "CREDENTIAL", "AUTH", "Authorization", "refresh_token"} {
			t.Run(shape+"/"+name, func(t *testing.T) {
				assertParitySecretRedacted(t, paritySecretAsset(shape, name, "fixtureSensitiveValue"), "fixtureSensitiveValue", 1)
			})
		}
		for _, name := range []string{"PORT", "REGION", "ordinary", "MODE"} {
			t.Run(shape+"/benign/"+name, func(t *testing.T) {
				assertParitySecretRedacted(t, paritySecretAsset(shape, name, "innocuous"), "innocuous", 0)
			})
		}
	}
}

func TestConfigurationSecretsLambdaValueParity(t *testing.T) {
	values := []string{
		"AKIA" + strings.Repeat("A", 16), "akia" + strings.Repeat("a", 16),
		"-----BEGIN CERTIFICATE-----", "-----BEGIN RSA PRIVATE KEY-----",
		"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
		"eyJ" + strings.Repeat("a", 10),
		"github_pat_" + strings.Repeat("a", 20), "glpat-" + strings.Repeat("a", 20),
		"AIza" + strings.Repeat("a", 35), "ya29." + strings.Repeat("a", 20),
	}
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		values = append(values, prefix+strings.Repeat("a", 36))
	}
	for _, shape := range []string{"run_env", "function_map", "compute_metadata"} {
		for i, value := range values {
			t.Run(shape+"/"+string(rune('A'+i)), func(t *testing.T) {
				assertParitySecretRedacted(t, paritySecretAsset(shape, "innocuous", value), value, 1)
			})
		}
	}
}

func TestConfigurationSecretsLambdaValueBoundaries(t *testing.T) {
	// Preserve source heuristic thresholds, not stricter valid-token formats.
	for _, value := range []string{"AKIA" + strings.Repeat("A", 15), "ASIA" + strings.Repeat("A", 16), "-----BEGI", "xoxq-", "eyJ" + strings.Repeat("a", 9), "ghp_" + strings.Repeat("a", 35), "ghq_" + strings.Repeat("a", 36), "github_pat_" + strings.Repeat("a", 19), "glpat-" + strings.Repeat("a", 19), "normal configuration"} {
		assertParitySecretRedacted(t, paritySecretAsset("run_env", "innocuous", value), value, 0)
	}
	for _, value := range []string{"prefix AKIA" + strings.Repeat("A", 16) + " suffix", "ghp_" + strings.Repeat("a", 37), "github_pat_" + strings.Repeat("a", 21), "glpat-" + strings.Repeat("a", 21)} {
		assertParitySecretRedacted(t, paritySecretAsset("run_env", "innocuous", value), value, 1)
	}
}

func TestConfigurationSecretsReferenceBoundaries(t *testing.T) {
	for _, value := range []string{"", "[REDACTED]", "${TOKEN}", "$SECRET", "$SECRET_VALUE", "projects/demo/secrets/password", "projects/123/secrets/password/versions/latest", "//secretmanager.googleapis.com/projects/demo/secrets/password/versions/1", "true", "false"} {
		assertParitySecretRedacted(t, paritySecretAsset("run_env", "TOKEN", value), value, 0)
	}
	token := "ghp_" + strings.Repeat("a", 36)
	for _, value := range []string{"https://example.invalid/secrets/path?value=" + token, "projects/demo/secrets/password?value=" + token, "${PLACEHOLDER} " + token, "$SECRET_PLACEHOLDER " + token, "/secrets/" + token} {
		assertParitySecretRedacted(t, paritySecretAsset("run_env", "innocuous", value), value, 1)
	}
	for _, key := range []string{"valueSource", "valueFrom", "secretKeyRef", "secretVersion", "secretEnvironmentVariables", "secretVolumes", "availableSecrets"} {
		a := inventory.NewAsset("fixture", "run.googleapis.com/Service", inventory.Object{key: inventory.Object{"TOKEN": token}})
		assertParitySecretRedacted(t, a, token, 0)
	}
}

func TestConfigurationSecretsParityDeduplicatesAndSorts(t *testing.T) {
	value := "ghp_" + strings.Repeat("a", 36)
	assertParitySecretRedacted(t, paritySecretAsset("run_env", "TOKEN", value), value, 1)
	a := inventory.NewAsset("fixture", "run.googleapis.com/Service", inventory.Object{"environmentVariables": inventory.Object{"TOKEN_Z": "fixtureSensitiveValueZ", "TOKEN_A": "fixtureSensitiveValueA"}})
	one, _ := json.Marshal(configurationSecrets(a, time.Time{}))
	for i := 0; i < 20; i++ {
		next, _ := json.Marshal(configurationSecrets(a, time.Time{}))
		if string(next) != string(one) {
			t.Fatal("nondeterministic map traversal")
		}
	}
	if strings.Index(string(one), "TOKEN_A") > strings.Index(string(one), "TOKEN_Z") {
		t.Fatal("unsorted paths")
	}
}
