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

func TestManagedRotationLifecycleOnlyReportComposition(t *testing.T) {
	const name = "//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/db"
	const uid = "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/opaque"
	secret := inventory.NewAsset(name, "secretmanager.googleapis.com/Secret", inventory.Object{"name": "projects/123/locations/us-central1/secrets/db", "secretType": "CLOUD_SQL_DB_CREDENTIALS", "policyMember": inventory.Object{"iamPolicyUidPrincipal": uid}})
	caller := inventory.NewAsset("caller", inventory.PermissionGrantType, inventory.Object{"principal": "user:operator@example.test", "resource": "projects/123", "permissions": []any{"secretmanager.secrets.enableManagedRotation"}})
	update := inventory.NewAsset("update", inventory.PermissionGrantType, inventory.Object{"principal": uid, "resource": "projects/999", "permissions": []any{"cloudsql.users.update"}})
	list := inventory.NewAsset("list", inventory.PermissionGrantType, inventory.Object{"principal": uid, "resource": "projects/999", "permissions": []any{"cloudsql.users.list"}})
	snap := inventory.Snapshot{Assets: []inventory.Asset{secret, caller, update, list}}
	selected, err := checks.Select([]string{"secret_manager_lifecycle"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, snap, selected, false); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := e.DB().QueryRow("SELECT count(*) FROM findings WHERE module='secret_manager_lifecycle'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected composed prerequisite finding, got %d", count)
	}
	for _, file := range []string{"findings.json", "report.html"} {
		data, err := os.ReadFile(filepath.Join(e.Dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{uid, "cloudsql.users.update", "secretmanager.secrets.enableManagedRotation"} {
			if !bytes.Contains(data, []byte(want)) {
				t.Fatalf("%s missing %s", file, want)
			}
		}
	}
}
