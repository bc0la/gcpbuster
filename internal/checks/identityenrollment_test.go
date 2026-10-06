package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIdentityPlatformEnrollmentExplicitGates(t *testing.T) {
	for _, tc := range []struct {
		typ, body string
		want      int
	}{
		{"Config", `{"client":{"permissions":{"disabledUserSignup":false}},"signIn":{"email":{"enabled":true,"passwordRequired":false}}}`, 1},
		{"Config", `{"signIn":{"email":{"enabled":true}}}`, 0},
		{"Config", `{"client":{"permissions":{"disabledUserSignup":true}},"signIn":{"anonymous":{"enabled":true}}}`, 0},
		{"Config", `{"client":{"permissions":{"disabledUserSignup":"false"}},"signIn":{"email":{"enabled":true}}}`, 0},
		{"Config", `{"client":{"permissions":{"disabledUserSignup":false}},"signIn":{"email":{"enabled":"true"}}}`, 0},
		{"Config", `{"client":{"permissions":{"disabledUserSignup":false}},"signIn":{"phoneNumber":{"enabled":true}}}`, 1},
		{"Tenant", `{"allowPasswordSignup":true}`, 0},
		{"Tenant", `{"client":{"permissions":{"disabledUserSignup":false}},"allowPasswordSignup":true}`, 0},
		{"Tenant", `{"client":{"permissions":{"disabledUserSignup":false}},"disableAuth":true,"allowPasswordSignup":true}`, 0},
		{"Tenant", `{"client":{"permissions":{"disabledUserSignup":false}},"disableAuth":false,"allowPasswordSignup":true}`, 1},
		{"Tenant", `{"client":{"permissions":{"disabledUserSignup":false}},"disableAuth":false,"enableAnonymousUser":true}`, 1},
		{"Tenant", `{"client":{"permissions":{"disabledUserSignup":false}},"disableAuth":false,"enableEmailLinkSignin":true}`, 1},
	} {
		got := identityPlatformEnrollment(asset("identitytoolkit.googleapis.com/"+tc.typ, tc.body), time.Now())
		if len(got) != tc.want {
			t.Fatalf("%s: %+v", tc.body, got)
		}
	}
}

func TestIdentityPlatformEnrollmentSafeEvidence(t *testing.T) {
	a := asset("identitytoolkit.googleapis.com/Config", `{"client":{"apiKey":"SENTINEL","permissions":{"disabledUserSignup":false}},"signIn":{"email":{"enabled":true,"passwordRequired":"SENTINEL"},"phoneNumber":{"enabled":true,"testPhoneNumbers":{"SENTINEL":"SENTINEL"}}}}`)
	got := identityPlatformEnrollment(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") || strings.Contains(string(raw), "email_password_required") {
		t.Fatal(string(raw))
	}
	a.Type = "unsupported"
	if len(identityPlatformEnrollment(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}
