package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/kingfisher"
	"github.com/bc0la/gcpbuster/internal/testfixture"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretsActualAndRedactedReportPipeline(t *testing.T) {
	const secret = "EXAMPLE_SECRET_FOR_TEST_ONLY"
	for _, redact := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual", true: "redacted"}[redact], func(t *testing.T) {
			resource := "//appengine.googleapis.com/apps/demo/services/default/versions/v1"
			original := inventory.NewAsset(resource, "appengine.googleapis.com/Version", inventory.Object{})
			original.Ancestors = []string{"projects/123"}
			snap := inventory.Snapshot{Assets: []inventory.Asset{original}}
			capture := inventory.NewSecretCapture(10, 4096, 8192)
			capture.Add(inventory.SecretSample{SourceType: "appengine_env", Resource: resource, Path: "envVariables.PASSWORD", Data: []byte("PASSWORD=" + secret)})
			runner := func(_ context.Context, input []kingfisher.Sample, options kingfisher.Options) (kingfisher.Report, error) {
				if len(input) != 1 || options.Redact != redact {
					t.Fatal("wrong scanner inputs/options")
				}
				return kingfisher.Report{SamplesScanned: 1, Findings: []kingfisher.Finding{{SampleID: input[0].ID, RuleID: "test", RuleName: "test detector", Snippet: secret, Confidence: "high", Validation: "not_attempted", Line: 1}}}, nil
			}
			prepareSecrets(context.Background(), &snap, capture, redact, true, true, runner)
			selected, err := checks.Select([]string{"secrets_scan", "configuration_plaintext"}, nil, nil)
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
			for _, name := range []string{"findings.json", "report.html", "engagement.db"} {
				data, err := os.ReadFile(filepath.Join(e.Dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte(secret)) == redact {
					t.Fatalf("wrong value retention in %s", name)
				}
			}
			var rawCount int
			if err := e.DB().QueryRow("SELECT count(*) FROM findings WHERE raw_output_path IS NOT NULL").Scan(&rawCount); err != nil {
				t.Fatal(err)
			}
			if redact && rawCount != 0 {
				t.Fatal("redacted artifacts persisted")
			}
			if !redact && rawCount != 2 {
				t.Fatal("missing finding-bound source artifacts", rawCount)
			}
			if redact {
				encoded, _ := json.Marshal(snap)
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("transient capture leaked into snapshot")
				}
			} else {
				snap.SecretValueMode = "redacted"
				if err := assess(context.Background(), cmd, e, snap, selected, false); err == nil || !strings.Contains(err.Error(), "fresh directory") {
					t.Fatal("raw engagement reused as redacted", err)
				}
			}
		})
	}
}

func TestInstalledKingfisherCLIReporting(t *testing.T) {
	if os.Getenv("GCPBUSTER_KINGFISHER_SMOKE") != "1" {
		t.Skip("optional pinned Kingfisher integration")
	}
	toolDir, err := filepath.Abs("../../.tools/kingfisher-v1.112.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Generated synthetic rule fixture; credential validation stays disabled.
	fake := testfixture.GitHubToken()
	fixture := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/example", "cloudfunctions.googleapis.com/CloudFunction", inventory.Object{"environmentVariables": inventory.Object{"GITHUB_TOKEN": fake}})}}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, redact := range []bool{false, true} {
		out := filepath.Join(t.TempDir(), "engagement")
		args := []string{"scan", "--inventory", input, "--modules", "secrets_scan,configuration_plaintext", "--engagement", out}
		if redact {
			args = append(args, "--redact-secrets")
		}
		cmd := rootCommand()
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, filename := range []string{"findings.json", "report.html", "engagement.db"} {
			contents, err := os.ReadFile(filepath.Join(out, filename))
			if err != nil || bytes.Contains(contents, []byte(fake)) == redact {
				t.Fatalf("unexpected %s actual-value retention (redact=%v): %v", filename, redact, err)
			}
		}
		findings, _ := os.ReadFile(filepath.Join(out, "findings.json"))
		if !bytes.Contains(findings, []byte("secrets_scan")) {
			t.Fatal("Kingfisher did not reach reporting")
		}
	}
}
