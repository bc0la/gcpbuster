package sourceaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditDoesNotTreatReferencesAsCoverage(t *testing.T) {
	root := t.TempDir()
	aws := t.TempDir()
	for _, path := range []string{filepath.Join(root, "src/pentesting-cloud/gcp-security/gcp-persistence"), filepath.Join(root, "src/pentesting-cloud/workspace-security"), filepath.Join(aws, "internal/module/public_sqs"), filepath.Join(aws, "internal/module/new_module")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	body := "# GCP test\n## Actual section\n`iam.serviceAccounts.getAccessToken`\n```bash\n## not a heading\n```\n~~~\n### also code\n~~~\n"
	path := filepath.Join(root, "src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-scheduler-persistence.md")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := Inspect(root, aws)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Pages) != 1 || len(a.Pages[0].Sections) != 2 || a.Pages[0].Status != "reference_only" {
		t.Fatal(a)
	}
	if a.Summary["behaviorally_verified_sections"] != 0 || len(a.Pages[0].ClassifiedPermissions) != 1 {
		t.Fatal(a.Summary)
	}
	for _, section := range a.Pages[0].Sections {
		if section.Status != "unverified" {
			t.Fatal("reference overclaimed")
		}
	}
	if len(a.Equivalents) != 2 || len(a.Equivalents[0].Candidates) != 0 || a.Equivalents[0].Status != "review_required" {
		t.Fatal(a.Equivalents)
	}
}
