package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConfigurationSecretsCodeBuildConnectionNameFamilies(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "APP_CONNECTION_STRING", "JDBC_URL", "PASSWORD"} {
		a := asset("cloudbuild.googleapis.com/Build", `{"steps":[{"env":["`+name+`=PRIVATE_CONNECTION_VALUE"]}]}`)
		got := configurationSecrets(a, time.Now())
		if len(got) != 1 {
			t.Fatal(name, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_CONNECTION_VALUE") {
			t.Fatal("credential candidate leaked", string(b))
		}
		for _, value := range []string{"", "true", "false", "${DATABASE_URL}", "projects/demo/secrets/connection/versions/latest"} {
			a.Resource.Data = map[string]any{name: value}
			if got := configurationSecrets(a, time.Now()); len(got) != 0 {
				t.Fatal("reference/placeholder is not plaintext", name, value, got)
			}
			a.Resource.Data = map[string]any{"steps": []any{map[string]any{"env": []any{name + "=" + value}}}}
			if got := configurationSecrets(a, time.Now()); len(got) != 0 {
				t.Fatal("native reference/placeholder is not plaintext", name, value, got)
			}
		}
	}
}
