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

func TestSQLUserUpdateAuditIndependentSelectionReport(t *testing.T) {
	project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/sql-project", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": ""})
	project.IAM = inventory.Object{}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var selected []checks.Check
	for _, c := range checks.All {
		if c.ID == "cloud_sql_user_update_audit" {
			selected = append(selected, c)
		}
	}
	if len(selected) != 1 || selected[0].Category != "best_practices" {
		t.Fatal(selected)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, inventory.Snapshot{Assets: []inventory.Asset{project}}, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"cloud_sql_user_update_audit", "cloudsql.googleapis.com", "DATA_WRITE", "cloudsql.users.update", "sql-project"} {
		if !bytes.Contains(b, []byte(text)) {
			t.Fatalf("missing %s: %s", text, b)
		}
	}
}
