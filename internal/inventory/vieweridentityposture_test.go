package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerIdentityProviderProjectionTypedAndRedacted(t *testing.T) {
	var raw Object
	json.Unmarshal([]byte(`{"name":"projects/123/config","client":{"apiKey":"SENTINEL","permissions":{"disabledUserSignup":false,"disabledUserDeletion":"SENTINEL"}},"signIn":{"email":{"enabled":true,"passwordRequired":false},"anonymous":{"enabled":true},"phoneNumber":{"enabled":true,"testPhoneNumbers":{"SENTINEL":"SENTINEL"}},"hashConfig":{"signerKey":"SENTINEL"}},"mfa":{"state":"MANDATORY"}}`), &raw)
	clean, err := viewerIdentityPosture(raw)
	encoded, _ := json.Marshal(clean)
	if err != nil || strings.Contains(string(encoded), "SENTINEL") || Get(clean, "signIn", "email", "enabled") != true || Get(clean, "client", "permissions", "disabledUserSignup") != false {
		t.Fatal(clean, err)
	}
	for _, bad := range []string{`{"signIn":true}`, `{"client":{"permissions":{"disabledUserSignup":"false"}}}`, `{"mfa":{"state":"SENTINEL"}}`, `{"enableAnonymousUser":1}`} {
		var d Object
		json.Unmarshal([]byte(bad), &d)
		d["allowPasswordSignup"] = true
		clean, err = viewerIdentityPosture(d)
		encoded, _ = json.Marshal(clean)
		if err == nil || clean["allowPasswordSignup"] != true || strings.Contains(string(encoded), "SENTINEL") {
			t.Fatal(clean, err)
		}
	}
}

func TestViewerIdentityMalformedRowsRetainLaterProviders(t *testing.T) {
	c := viewerDataClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			return response(200, `{"name":"projects/123/config","signIn":{"email":{"enabled":true,"passwordRequired":"SENTINEL"}},"client":{"permissions":{"disabledUserSignup":false}}}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/tenants") {
			return response(200, `{"tenants":[{"name":"projects/999/tenants/bad"},{"name":"projects/123/tenants/good","allowPasswordSignup":true,"disableAuth":false,"client":{"permissions":{"disabledUserSignup":false}}}]}`), nil
		}
		return response(403, "SENTINEL"), nil
	})
	var out Snapshot
	c.viewerIdentityConfig(context.Background(), &out, "demo", "projects/123")
	if len(out.Assets) != 2 || !hasCoverage(out, "failed") || out.Assets[1].Resource.Data["allowPasswordSignup"] != true {
		t.Fatal(out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
}
