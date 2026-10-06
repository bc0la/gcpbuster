package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestServiceConfigSecretsSafeCandidates(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/ServiceConfig", `{"_gcpbusterSecretCandidates":[{"rule":"url_credentials","value":"NEVER_SAVE"},{"rule":"url_credentials"},{"rule":"NEVER_SAVE"}]}`)
	got := serviceConfigSecrets(a, time.Time{})
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "NEVER_SAVE") {
		t.Fatal(string(b))
	}
	a.Type = "servicemanagement.googleapis.com/ManagedService"
	if len(serviceConfigSecrets(a, time.Time{})) != 0 {
		t.Fatal("wrong type")
	}
}
