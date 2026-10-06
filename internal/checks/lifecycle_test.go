package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestSecretAliasStateCorrelation(t *testing.T) {
	name := "//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/s"
	secret := inventory.NewAsset(name, "secretmanager.googleapis.com/Secret", inventory.Object{"versionAliases": map[string]any{"prod": "2", "old": "1", "unknown": "3"}, "gcpbusterAliasesObserved": true})
	assets := []inventory.Asset{secret, inventory.NewAsset(name+"/versions/1", "secretmanager.googleapis.com/SecretVersion", inventory.Object{"state": "DESTROYED"}), inventory.NewAsset(name+"/versions/2", "secretmanager.googleapis.com/SecretVersion", inventory.Object{"state": "ENABLED"}), inventory.NewAsset("//secretmanager.googleapis.com/projects/other/locations/us-central1/secrets/s/versions/3", "secretmanager.googleapis.com/SecretVersion", inventory.Object{"state": "DISABLED"})}
	rows := SecretAliasAssets(assets)
	if len(rows) != 3 {
		t.Fatal(rows)
	}
	for _, a := range rows {
		got := secretManagerLifecycle(a, time.Now())
		if len(got) != 1 {
			t.Fatal(got)
		}
		alias := a.Resource.Data["alias"]
		if alias == "old" && got[0].Severity != "low" {
			t.Fatal(got)
		}
		if alias == "unknown" && got[0].Evidence["observed_state"] != "UNKNOWN" {
			t.Fatal("foreign state correlated")
		}
	}
	assets = append(assets, inventory.NewAsset(name+"/versions/2", "secretmanager.googleapis.com/SecretVersion", inventory.Object{"state": "DISABLED"}))
	for _, a := range SecretAliasAssets(assets) {
		if a.Resource.Data["alias"] == "prod" && a.Resource.Data["state"] != "UNKNOWN" {
			t.Fatal("conflicting state treated as healthy")
		}
	}
}

func TestSecretManagedRotationAndCMEKMetadata(t *testing.T) {
	for _, tc := range []struct {
		body     string
		want     int
		severity string
	}{
		{`{"secretType":"CLOUD_SQL_DB_CREDENTIALS","rotation":{"managedRotationStatus":{"state":"ACTIVE"}}}`, 1, "info"},
		{`{"secretType":"CLOUD_SQL_DB_CREDENTIALS","rotation":{"managedRotationStatus":{"state":"INACTIVE","error":{"message":"DO_NOT_KEEP"}}}}`, 1, "low"},
		{`{"secretType":"CLOUD_SQL_DB_CREDENTIALS"}`, 0, ""},
		{`{"secretType":"CLOUD_SQL_DB_CREDENTIALS","rotation":{"managedRotationStatus":{"state":"STATE_UNSPECIFIED"}}}`, 0, ""},
		{`{"rotation":{"managedRotationStatus":{"state":"ACTIVE"}}}`, 0, ""},
		{`{"customerManagedEncryption":{"kmsKeyName":"projects/other/locations/us-central1/keyRings/r/cryptoKeys/k"}}`, 1, "info"},
		{`{"customerManagedEncryption":{"kmsKeyName":"https://evil.test/key"}}`, 0, ""},
	} {
		got := secretManagerLifecycle(asset("secretmanager.googleapis.com/Secret", tc.body), time.Now())
		if len(got) != tc.want {
			t.Fatal(got)
		}
		if tc.want > 0 && got[0].Severity != tc.severity {
			t.Fatal(got)
		}
	}
}

func TestSecretLifecycleBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, kind, data string
		want             int
	}{
		{"missing", "Secret", `{}`, 0},
		{"future", "Secret", `{"rotation":{"nextRotationTime":"2026-11-01T00:00:00Z"}}`, 0},
		{"grace", "Secret", `{"rotation":{"nextRotationTime":"2026-10-04T12:00:00Z"}}`, 0},
		{"overdue", "Secret", `{"rotation":{"nextRotationTime":"2026-10-01T00:00:00Z"}}`, 1},
		{"invalid time", "Secret", `{"rotation":{"nextRotationTime":"bad"}}`, 0},
		{"incomplete schedule", "Secret", `{"rotation":{"rotationPeriod":"86400s"}}`, 1},
		{"topics no rotation", "Secret", `{"topics":[{"name":"projects/p/topics/t"}]}`, 1},
		{"delayed destruction", "Secret", `{"versionDestroyTtl":"86400000s"}`, 1},
		{"invalid duration", "Secret", `{"versionDestroyTtl":"bad"}`, 0},
		{"disabled recoverable", "SecretVersion", `{"state":"DISABLED","scheduledDestroyTime":"2026-11-01T00:00:00Z"}`, 1},
		{"already destroyed", "SecretVersion", `{"state":"DESTROYED","scheduledDestroyTime":"2026-11-01T00:00:00Z"}`, 0},
		{"disabled without destruction", "SecretVersion", `{"state":"DISABLED"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := secretManagerLifecycle(asset("secretmanager.googleapis.com/"+tc.kind, tc.data), now); len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestKMSLifecycleBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, kind, data string
		want             int
	}{
		{"missing", "CryptoKey", `{}`, 0},
		{"eligible no schedule", "CryptoKey", `{"name":"key","createTime":"2025-01-01T00:00:00Z","purpose":"ENCRYPT_DECRYPT","versionTemplate":{"protectionLevel":"SOFTWARE"}}`, 1},
		{"asymmetric", "CryptoKey", `{"name":"key","createTime":"2025-01-01T00:00:00Z","purpose":"ASYMMETRIC_SIGN","versionTemplate":{"protectionLevel":"SOFTWARE"}}`, 0},
		{"external", "CryptoKey", `{"name":"key","createTime":"2025-01-01T00:00:00Z","purpose":"ENCRYPT_DECRYPT","versionTemplate":{"protectionLevel":"EXTERNAL"}}`, 0},
		{"imported only", "CryptoKey", `{"purpose":"ENCRYPT_DECRYPT","importOnly":true,"nextRotationTime":"2026-01-01T00:00:00Z","versionTemplate":{"protectionLevel":"HSM"}}`, 0},
		{"overdue", "CryptoKey", `{"purpose":"ENCRYPT_DECRYPT","nextRotationTime":"2026-01-01T00:00:00Z","versionTemplate":{"protectionLevel":"HSM"}}`, 1},
		{"scheduled destroy", "CryptoKeyVersion", `{"state":"DESTROY_SCHEDULED","destroyTime":"2026-11-01T00:00:00Z"}`, 1},
		{"destroyed", "CryptoKeyVersion", `{"state":"DESTROYED","destroyTime":"2026-11-01T00:00:00Z"}`, 0},
		{"invalid time", "CryptoKeyVersion", `{"state":"DESTROY_SCHEDULED","destroyTime":"bad"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kmsLifecycle(asset("cloudkms.googleapis.com/"+tc.kind, tc.data), now); len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestSecretExpirationIsMetadataNotDeletionProof(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ body, severity string }{
		{`{"expireTime":"2026-10-06T00:00:00Z"}`, "info"},
		{`{"expireTime":"2026-10-05T00:00:00Z"}`, "low"},
		{`{"expireTime":"2026-10-04T19:00:00-05:00"}`, "low"},
		{`{"expireTime":"bad"}`, ""}, {`{"expireTime":false}`, ""}, {`{"ttl":"86400s"}`, ""}, {`{}`, ""},
	} {
		got := secretManagerLifecycle(asset("secretmanager.googleapis.com/Secret", tc.body), now)
		if tc.severity == "" {
			if len(got) != 0 {
				t.Fatal(got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != tc.severity || got[0].Evidence["assessment"] == nil {
			t.Fatal(got)
		}
	}
	if got := secretManagerLifecycle(asset("secretmanager.googleapis.com/SecretVersion", `{"expireTime":"2026-10-06T00:00:00Z"}`), now); len(got) != 0 {
		t.Fatal(got)
	}
}
