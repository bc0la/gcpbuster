package checks

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestComposerWebserverAdmissionNotAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		want         int
	}{
		{"both-families-dedup", `{"allowedIpRanges":[{"value":"::/0"},{"value":"0.0.0.0/0"},{"value":"0.0.0.0/0"}]}`, 2},
		{"restricted", `{"allowedIpRanges":[{"value":"192.0.2.0/24"},{"value":"2001:db8::/32"}]}`, 0},
		{"single-address", `{"allowedIpRanges":[{"value":"0.0.0.0"}]}`, 0},
		{"invalid-cidr", `{"allowedIpRanges":[{"value":"garbage/0"},{"value":"192.0.2.1/0"}]}`, 0},
		{"malformed-row", `{"allowedIpRanges":[null,42,{"value":false},{"description":"0.0.0.0/0"}]}`, 0},
		{"malformed-list", `{"allowedIpRanges":"0.0.0.0/0"}`, 0},
		{"empty", `{"allowedIpRanges":[]}`, 0},
		{"missing", `{}`, 0},
		{"null", `null`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset("composer.googleapis.com/Environment", fmt.Sprintf(`{"config":{"webServerNetworkAccessControl":%s,"privateEnvironmentConfig":{"networkingType":"PRIVATE"}}}`, tc.config))
			got := composerNetwork(a, time.Now())
			if len(got) != tc.want {
				t.Fatalf("want %d: %+v", tc.want, got)
			}
			for _, r := range got {
				if r.Severity != "medium" || !strings.Contains(fmt.Sprint(r.Evidence["assessment"]), "authentication") {
					t.Fatal(r)
				}
			}
			if len(got) == 2 && got[0].Evidence["network"] != "0.0.0.0/0" {
				t.Fatal("nondeterministic network order", got)
			}
		})
	}
}

func TestComposerPublicNetworkingExplicitEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		want         int
	}{
		{"modern-public", `{"networkingType":"PUBLIC"}`, 1},
		{"legacy-public", `{"enablePrivateEnvironment":false}`, 1},
		{"consistent-public", `{"networkingType":"PUBLIC","enablePrivateEnvironment":false}`, 1},
		{"modern-private", `{"networkingType":"PRIVATE"}`, 0},
		{"legacy-private", `{"enablePrivateEnvironment":true}`, 0},
		{"conflict-public", `{"networkingType":"PUBLIC","enablePrivateEnvironment":true}`, 0},
		{"conflict-private", `{"networkingType":"PRIVATE","enablePrivateEnvironment":false}`, 0},
		{"unspecified-modern", `{"networkingType":"NETWORKING_TYPE_UNSPECIFIED","enablePrivateEnvironment":false}`, 0},
		{"malformed-modern", `{"networkingType":false,"enablePrivateEnvironment":false}`, 0},
		{"malformed-legacy", `{"networkingType":"PUBLIC","enablePrivateEnvironment":"false"}`, 0},
		{"missing", `{}`, 0},
		{"null", `null`, 0},
		{"public-range-not-public-mode", `{"enablePrivatelyUsedPublicIps":true}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := composerNetwork(asset("composer.googleapis.com/Environment", fmt.Sprintf(`{"config":{"privateEnvironmentConfig":%s}}`, tc.config)), time.Now())
			if len(got) != tc.want {
				t.Fatalf("want %d: %+v", tc.want, got)
			}
			for _, r := range got {
				if r.Severity != "info" || !strings.Contains(fmt.Sprint(r.Evidence["assessment"]), "does not establish public worker IP") {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestComposerNetworkIgnoresSensitiveConfiguration(t *testing.T) {
	a := asset("composer.googleapis.com/Environment", `{"config":{"airflowUri":"https://secret.example.invalid","dagGcsPrefix":"gs://secret-bucket/dags","softwareConfig":{"envVariables":{"PASSWORD":"DO_NOT_PERSIST"}},"privateEnvironmentConfig":{"networkingType":"PUBLIC"},"webServerNetworkAccessControl":{"allowedIpRanges":[{"value":"0.0.0.0/0","description":"DO_NOT_PERSIST"}]}}}`)
	got := composerNetwork(a, time.Now())
	if len(got) != 2 {
		t.Fatal(got)
	}
	data, err := json.Marshal(got)
	if err != nil || strings.Contains(string(data), "DO_NOT_PERSIST") || strings.Contains(string(data), "secret.example") || strings.Contains(string(data), "secret-bucket") {
		t.Fatalf("unexpected evidence: %s %v", data, err)
	}
}
