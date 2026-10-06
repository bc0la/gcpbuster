package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestViewerConstraintRejectsOtherAuthority(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--project", "my-project", "--impersonate-service-account", "sa@example.com"},
		{"scan", "--workspace-customer", "my_customer"},
		{"scan", "--project", "my-project", "--workspace-tokens"},
		{"scan", "--project", "my-project", "--workspace-token-env", "TOKEN"},
		{"scan", "--project", "my-project", "--workspace-members"},
		{"scan", "--project", "my-project", "--scan-gcs-content"},
		{"scan", "--project", "my-project", "--scan-source-archives"},
		{"scan", "--project", "my-project", "--anonymous-storage"},
		{"scan", "--project", "my-project", "--iap-policies"},
		{"collect", "--scope", "projects/my-project", "--engagement", t.TempDir()},
	} {
		cmd := rootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "viewer") {
			t.Fatal(args, err)
		}
	}
}
