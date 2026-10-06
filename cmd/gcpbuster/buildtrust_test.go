package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildOnlyAssessmentExpandsScopedIdentityGrants(t *testing.T) {
	trigger := inventory.NewAsset("//cloudbuild.googleapis.com/projects/demo/locations/global/triggers/pr", "cloudbuild.googleapis.com/BuildTrigger", inventory.Object{
		"serviceAccount": "projects/demo/serviceAccounts/build@demo.iam.gserviceaccount.com",
		"github":         inventory.Object{"owner": "example", "name": "repo", "pullRequest": inventory.Object{"commentControl": "COMMENTS_DISABLED"}},
	})
	project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", inventory.Object{})
	project.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/testBuild", "members": []any{"serviceAccount:build@demo.iam.gserviceaccount.com"}}}}
	role := inventory.NewAsset("//iam.googleapis.com/roles/testBuild", "iam.googleapis.com/Role", inventory.Object{"name": "roles/testBuild", "includedPermissions": []any{"iam.serviceAccounts.getAccessToken"}})
	snapshot := inventory.Snapshot{Assets: []inventory.Asset{trigger, project, role}}
	selected, err := checks.Select([]string{"cloud_build_pr_comment_control"}, nil, nil)
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
	if err := assess(context.Background(), cmd, e, snapshot, selected, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Detail string }
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatal("missing PR finding", string(data))
	}
	var detail inventory.Object
	if err := json.Unmarshal([]byte(rows[0].Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if len(inventory.List(inventory.Get(detail, "evidence", "build_trust_context", "high_impact_direct_grants"))) != 1 {
		t.Fatal("build-only assessment omitted grant expansion", detail)
	}
}
