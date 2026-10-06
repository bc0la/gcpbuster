package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/kingfisher"
)

func TestApigeeConfigurationActualRedactedReport(t *testing.T) {
	const secret = "APIGEE_WEAK_PASSWORD_FULL_VALUE"
	for _, redact := range []bool{false, true} {
		resource := "//apigee.googleapis.com/organizations/demo/apis/api/revisions/3"
		capture := inventory.NewSecretCapture(10, 4096, 8192)
		capture.Add(inventory.SecretSample{SourceType: "apigee_bundle_config", Resource: resource, Path: "bundle[apiproxy/policies/config.xml].xml", Data: []byte(`<AssignMessage name="config"><Password>` + secret + `</Password></AssignMessage>`)})
		capture.Add(inventory.SecretSample{SourceType: "apigee_bundle_config", Resource: resource, Path: "bundle[apiproxy/policies/config.xml].xml.elements[0].Password", Data: []byte("Password=" + secret)})
		snap := inventory.Snapshot{}
		run := func(_ context.Context, input []kingfisher.Sample, options kingfisher.Options) (kingfisher.Report, error) {
			if len(input) != 2 || options.Redact != redact {
				t.Fatal(input, options)
			}
			rawID := ""
			for _, sample := range input {
				if strings.HasPrefix(sample.Content, "<AssignMessage") {
					rawID = sample.ID
				}
			}
			if rawID == "" {
				t.Fatal("full XML source not supplied to Kingfisher")
			}
			return kingfisher.Report{SamplesScanned: 2, Findings: []kingfisher.Finding{{SampleID: rawID, RuleID: "test", RuleName: "fixture", Snippet: secret, Confidence: "high", Validation: "not_attempted", Line: 1}}}, nil
		}
		prepareSecrets(context.Background(), &snap, capture, redact, true, true, run)
		selected, err := checks.Select([]string{"configuration_plaintext", "secrets_scan"}, nil, nil)
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
		for _, file := range []string{"findings.json", "report.html", "engagement.db"} {
			b, err := os.ReadFile(filepath.Join(e.Dir, file))
			if err != nil || bytes.Contains(b, []byte(secret)) == redact {
				t.Fatal(file, redact, err)
			}
		}
		b, _ := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
		if !redact && (!bytes.Contains(b, []byte("format=bundle")) || !bytes.Contains(b, []byte("safe bounded ZIP reader")) || !bytes.Contains(b, []byte(`source_revision`)) || !bytes.Contains(b, []byte("sensitive_variable_name"))) {
			t.Fatal(string(b))
		}
		if redact {
			if _, err := os.Stat(filepath.Join(e.Dir, "secret-hits")); !os.IsNotExist(err) {
				t.Fatal("redacted artifacts", err)
			}
		}
	}
}

func TestApigeeManualRefetchRejectsUnreviewedInputs(t *testing.T) {
	s := inventory.SecretSample{SourceType: "apigee_bundle_config", Resource: "//apigee.googleapis.com/organizations/demo/sharedflows/flow/revisions/2", Path: "bundle[sharedflowbundle/policies/config.xml].xml"}
	if command := secretPullCommand(s); !strings.Contains(command, "format=bundle") || !strings.Contains(command, "--request GET") || secretSourceRevision(s) != "2" {
		t.Fatal(command)
	}
	s.Resource += "?callback=evil"
	if command := secretPullCommand(s); command != "" {
		t.Fatal(command)
	}
}
