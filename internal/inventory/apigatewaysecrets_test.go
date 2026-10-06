package inventory

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestAPIGatewaySecretsRedactedAndPartial(t *testing.T) {
	doc := func(source string) any {
		return Object{"document": Object{"path": "SECRET_FILENAME", "contents": base64.StdEncoding.EncodeToString([]byte(source))}}
	}
	raw := Object{"openapiDocuments": []any{doc("password: SUPER_SECRET_CANDIDATE\n"), Object{"document": Object{"contents": "%%%"}}, doc("x: harmless")}}
	got, err := projectAPIGatewaySecrets(raw)
	if err == nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") || !strings.Contains(string(b), "credential_assignment") {
		t.Fatal(string(b))
	}
	if _, err := projectAPIGatewaySecrets(Object{}); err == nil {
		t.Fatal("missing source passed")
	}
	if _, err := projectAPIGatewaySecrets(Object{"openapiDocuments": []any{doc("a\x00b")}}); err == nil {
		t.Fatal("binary passed")
	}
	if _, err := projectAPIGatewaySecrets(Object{"openapiDocuments": []any{doc(strings.Repeat("x", (4<<20)+1))}}); err == nil {
		t.Fatal("oversize passed")
	}
}
