package checks

import (
	"strings"
	"testing"
	"time"
)

func TestIdentityPlatformNativeTenantFields(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"enableAnonymousUser":true,"mfaConfig":{"state":"DISABLED"}}`, 2},
		{`{"enableAnonymousUser":false,"allowAnonymousSignup":true,"mfaConfig":{"state":"ENABLED"},"mfa":{"state":"DISABLED"}}`, 0},
		{`{"disableAuth":true,"enableAnonymousUser":true,"mfaConfig":{"state":"DISABLED"}}`, 0},
		{`{}`, 0},
		{`{"allowAnonymousSignup":true,"mfa":{"state":"DISABLED"}}`, 2},
	} {
		if got := identityPlatform(asset("identitytoolkit.googleapis.com/Tenant", tc.body), time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
	if got := identityPlatform(asset("identitytoolkit.googleapis.com/Config", `{"signIn":{"anonymous":{"enabled":true}},"mfa":{"state":"DISABLED"}}`), time.Now()); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestBigQueryConditionalPublicGrantIsNotUnconditional(t *testing.T) {
	a := asset("bigquery.googleapis.com/Dataset", `{"access":[{"iamMember":"allUsers","role":"READER","condition":{"expression":"request.time < timestamp('2020-01-01T00:00:00Z')"}}]}`)
	got := publicBigQuery(a, time.Now())
	if len(got) != 1 || got[0].Severity != "medium" || !strings.Contains(got[0].Title, "conditional") {
		t.Fatal(got)
	}
	if got := publicBigQuery(asset("bigquery.googleapis.com/Dataset", `{"access":[{"iamMember":"user:reader@example.com","role":"READER"}]}`), time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
	for _, condition := range []string{`{}`, `42`, `{"expression":" "}`} {
		got := publicBigQuery(asset("bigquery.googleapis.com/Dataset", `{"access":[{"iamMember":"allUsers","condition":`+condition+`}]}`), time.Now())
		if len(got) != 1 || !strings.Contains(got[0].Title, "unverified") {
			t.Fatal(got)
		}
	}
}
