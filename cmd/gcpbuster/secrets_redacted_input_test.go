package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestRedactedPolicyAlsoCoversSuppliedActualSecretRows(t *testing.T) {
	const secret = "SYNTHETIC_SUPPLIED_VALUE_DO_NOT_RETAIN"
	native := checks.CapturedSampleAssets([]inventory.SecretSample{{SourceType: "function_env", Resource: "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/f", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=" + secret)}}, false)[0]
	native.Resource.Data["pull_command"] = secret
	scanner := inventory.NewAsset("//gcpbuster.googleapis.com/secretFindings/test", checks.SecretScanFindingType, inventory.Object{"scanner": "kingfisher", "credential_validation_performed": false, "rule_id": "test", "match": secret, "source": secret, "source_field": secret, "pull_command": secret, "refetch_metadata": inventory.Object{"value": secret}, "confidence": "high", "validation": "not_attempted", "redacted": false})
	reference := inventory.NewAsset("//gcpbuster.googleapis.com/parameter-reference/supplied", checks.ParameterReferenceType, inventory.Object{"parameter_version": secret, "parameter": secret, "target_version": secret, "identity": secret, "identity_payload_grants": []any{inventory.Object{"principal": secret}}, "caller_render_grants": []any{inventory.Object{"principal": secret}}, "identity_state": "OBSERVED_UID", "reference_status": "STORED_REFERENCE", "observed_target_state": "UNKNOWN", "render_performed": false, "payload_read_performed": false, "redacted": false})
	snap := inventory.Snapshot{Assets: []inventory.Asset{native, scanner, reference}, SecretValueMode: "redacted", SecretArtifacts: map[string][]byte{native.Name: []byte(secret)}, SecretFingerprint: []byte(secret)}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	selected, err := checks.Select([]string{"secrets_scan", "configuration_plaintext", "parameter_reference_delegation"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, snap, selected, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"findings.json", "report.html", "engagement.db"} {
		data, err := os.ReadFile(filepath.Join(e.Dir, name))
		if err != nil || bytes.Contains(data, []byte(secret)) {
			t.Fatalf("supplied value retained in %s: %v", name, err)
		}
	}
	if native.Resource.Data["value"] != secret {
		t.Fatal("caller-owned actual asset mutated")
	}
	if reference.Resource.Data["target_version"] != secret {
		t.Fatal("caller-owned reference asset mutated")
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "secret-hits")); !os.IsNotExist(err) {
		t.Fatal("supplied artifact persisted", err)
	}
}
