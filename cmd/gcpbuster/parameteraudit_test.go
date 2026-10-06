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

func TestParameterAuditResolvedPolicyReporting(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/demo", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": "organizations/123"})
		org := inventory.NewAsset("//cloudresourcemanager.googleapis.com/organizations/123", "cloudresourcemanager.googleapis.com/Organization", inventory.Object{})
		org.IAM = inventory.Object{}
		project.IAM = inventory.Object{}
		if enabled {
			project.IAM["auditConfigs"] = []any{inventory.Object{"service": "parametermanager.googleapis.com", "auditLogConfigs": []any{inventory.Object{"logType": "DATA_READ"}}}}
		}
		snap := inventory.Snapshot{Assets: []inventory.Asset{project, org}}
		selected, err := checks.Select([]string{"parameter_manager_audit"}, nil, nil)
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
		if err := e.DB().QueryRow("SELECT count(*) FROM findings WHERE module='parameter_manager_audit'").Scan(&count); err != nil {
			e.Close()
			t.Fatal(err)
		}
		want := 2 // Complete organization and project policy chains.
		if enabled {
			want = 1 // Project enabled; organization remains independently disabled.
		}
		if count != want {
			e.Close()
			t.Fatalf("enabled=%v: got %d findings, want %d", enabled, count, want)
		}
		for _, name := range []string{"findings.json", "report.html"} {
			data, err := os.ReadFile(filepath.Join(e.Dir, name))
			if err != nil {
				e.Close()
				t.Fatal(err)
			}
			if !enabled && !bytes.Contains(data, []byte("parametermanager.googleapis.com")) {
				e.Close()
				t.Fatalf("service evidence missing from %s", name)
			}
		}
		e.Close()
	}
}
