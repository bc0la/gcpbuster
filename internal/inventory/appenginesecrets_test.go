package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAppEngineSecretsRedactedProjection(t *testing.T) {
	raw := Object{"envVariables": Object{"PRIVATE_PASSWORD_NAME": "PRIVATE_VALUE", "PUBLIC": "hello", "TOKEN_REF": "projects/demo/secrets/token/versions/latest", "TOKEN_PLACEHOLDER": "${TOKEN}", "AUTH": "false"}, "buildEnvVariables": Object{"KEY": "-----BEGIN PRIVATE KEY-----"}}
	got, err := projectAppEngineSecrets(raw)
	if err != nil || len(got) != 2 {
		t.Fatalf("candidates=%v err=%v", got, err)
	}
	b, _ := json.Marshal(got)
	for _, sentinel := range []string{"PRIVATE_PASSWORD_NAME", "PRIVATE_VALUE", "-----BEGIN", "TOKEN_REF", "projects/demo"} {
		if strings.Contains(string(b), sentinel) {
			t.Fatalf("retained sensitive input %q", sentinel)
		}
	}
	for _, row := range got {
		if len(Str(Obj(row)["name_digest"])) != 64 || len(Obj(row)) != 3 {
			t.Fatal(row)
		}
	}
}

func TestAppEngineSecretsCodeBuildConnectionNameFamilies(t *testing.T) {
	raw := Object{"envVariables": Object{"DATABASE_URL": "PRIVATE_VALUE", "CONNECTION_STRING": "PRIVATE_VALUE", "JDBC_URL": "PRIVATE_VALUE", "JDBC_REFERENCE": "projects/demo/secrets/database/versions/latest"}}
	got, err := projectAppEngineSecrets(raw)
	if err != nil || len(got) != 3 {
		t.Fatal(got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE_VALUE") || strings.Contains(string(b), "DATABASE_URL") || strings.Contains(string(b), "JDBC_REFERENCE") {
		t.Fatal("name/value leaked", string(b))
	}
}

func TestAppEngineSecretsPartialAndLimits(t *testing.T) {
	got, err := projectAppEngineSecrets(Object{"envVariables": Object{"PASSWORD": "value", "BAD": 1}, "buildEnvVariables": nil})
	if err == nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	got, err = projectAppEngineSecrets(Object{"envVariables": Object{"A_PASSWORD": "value", "Z": strings.Repeat("x", 4<<20)}})
	if err == nil || len(got) != 1 {
		t.Fatal(len(got), err)
	}
	values := Object{}
	for i := 0; i < 1001; i++ {
		values[fmt.Sprintf("PASSWORD_%04d", i)] = "value"
	}
	got, err = projectAppEngineSecrets(Object{"envVariables": values})
	if err == nil || len(got) != 1000 {
		t.Fatal(len(got), err)
	}
	if got, err = projectAppEngineSecrets(Object{}); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
}

func TestAppEngineSecretsLegacyValueFamilies(t *testing.T) {
	for _, value := range []string{"glpat-" + strings.Repeat("A", 20), "eyJ" + strings.Repeat("A", 10), "xoxb-short", "-----BEGIN CERTIFICATE-----", "github_pat_" + strings.Repeat("A", 20)} {
		got, err := projectAppEngineSecrets(Object{"envVariables": Object{"VALUE": value}})
		if err != nil || len(got) != 1 || Str(Obj(got[0])["rule"]) != "credential_pattern" {
			t.Fatal(got, err)
		}
	}
}
