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

func TestParameterReferenceOnlyActualAndRedactedReporting(t *testing.T) {
	const parameter = "//parametermanager.googleapis.com/projects/123/locations/global/parameters/db"
	const target = "//secretmanager.googleapis.com/projects/123/secrets/reference-reporting-target/versions/1"
	const unrelated = "UNRELATED_RAW_PARAMETER_VALUE_NOT_TO_PERSIST"
	for _, redact := range []bool{false, true} {
		metadata := inventory.NewAsset(parameter, "parametermanager.googleapis.com/Parameter", inventory.Object{"name": "projects/123/locations/global/parameters/db", "policyMember": inventory.Object{"iamPolicyUidPrincipal": "principal://parametermanager.googleapis.com/projects/123/uid/locations/global/parameters/opaque"}})
		snap := inventory.Snapshot{Assets: []inventory.Asset{metadata}}
		capture := inventory.NewSecretCapture(10, 4096, 8192)
		capture.Add(inventory.SecretSample{SourceType: "parameter_manager_raw", Resource: parameter + "/versions/v1", Path: "payload.data", Data: []byte("password: " + unrelated + "\nreference: __REF__(\"" + target + "\")\n")})
		prepareSecrets(context.Background(), &snap, capture, redact, false, false, nil)
		selected, err := checks.Select([]string{"parameter_reference_delegation"}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := rootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := assess(context.Background(), cmd, e, snap, selected, false); err != nil {
			e.Close()
			t.Fatal(err)
		}
		var count int
		if err := e.DB().QueryRow("SELECT count(*) FROM findings WHERE module='parameter_reference_delegation'").Scan(&count); err != nil {
			e.Close()
			t.Fatal(err)
		}
		if count != 1 {
			e.Close()
			t.Fatalf("expected reference-only finding, got %d", count)
		}
		for _, file := range []string{"findings.json", "report.html", "engagement.db"} {
			data, err := os.ReadFile(filepath.Join(e.Dir, file))
			if err != nil {
				e.Close()
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(unrelated)) {
				e.Close()
				t.Fatalf("unrelated raw value leaked to %s", file)
			}
			if bytes.Contains(data, []byte(target)) == redact {
				e.Close()
				t.Fatalf("wrong reference policy in %s", file)
			}
		}
		if _, err := os.Stat(filepath.Join(e.Dir, "secret-hits")); !os.IsNotExist(err) {
			e.Close()
			t.Fatal("reference-only artifact persisted", err)
		}
		e.Close()
	}
}
