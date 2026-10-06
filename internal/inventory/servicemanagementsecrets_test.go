package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceManagementSecretsProjection(t *testing.T) {
	raw := Object{"backend": Object{"rules": []any{Object{"address": "https://user:PRIVATE_PASSWORD@example.test/path"}}}, "sourceInfo": Object{"sourceFiles": []any{Object{"contents": "ghp_" + strings.Repeat("A", 36)}}}}
	got, err := projectServiceManagementSecrets(raw)
	if err != nil || len(got) != 1 || Str(Obj(got[0])["rule"]) != "url_credentials" {
		t.Fatal(got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "example") {
		t.Fatal(string(b))
	}
	if _, err := projectServiceManagementSecrets(Object{"backend": strings.Repeat("x", (4<<20)+1)}); err == nil {
		t.Fatal("over limit passed")
	}
}
