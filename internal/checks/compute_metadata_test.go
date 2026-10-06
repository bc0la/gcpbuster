package checks

import (
	"testing"
	"time"
)

func TestComputeMetadataLegacySettingsAreNotIMDSExposure(t *testing.T) {
	for _, data := range []string{
		`{}`,
		`{"metadata":{"items":[{"key":"enable-legacy-endpoints","value":"true"}]}}`,
		`{"metadata":{"items":[{"key":"disable-legacy-endpoints","value":"false"}]}}`,
		`{"metadata":{"items":[{"key":"enable-legacy-endpoints","value":true}]},"serviceAccounts":[{"email":"worker@example.iam.gserviceaccount.com"}]}`,
	} {
		if got := computeMetadata(asset("compute.googleapis.com/Instance", data), time.Now()); len(got) != 0 {
			t.Fatalf("retired endpoint configuration is not a live exposure: %+v", got)
		}
	}
}

func TestComputeMetadataCurrentIndicatorsRemain(t *testing.T) {
	a := asset("compute.googleapis.com/Instance", `{"metadata":{"items":[{"key":"enable-legacy-endpoints","value":"true"},{"key":"serial-port-enable","value":"true"},{"key":"enable-oslogin","value":"false"},{"key":"block-project-ssh-keys","value":"false"}]},"serviceAccounts":[{"email":"worker@example.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}]}`)
	got := computeMetadata(a, time.Now())
	if len(got) != 4 {
		t.Fatalf("expected three configuration indicators and informational OAuth scope: %+v", got)
	}
	if got[3].Severity != "info" || got[3].Evidence["assessment"] == nil {
		t.Fatalf("OAuth scope is not credential-exfiltration proof: %+v", got[3])
	}
}
