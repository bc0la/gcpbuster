package engagement

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestOpenReadOnlyExistingEngagement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "engagement")
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Write(context.Background(), findings.Finding{Title: "existing", Module: "public_iam"}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	before, err := os.ReadFile(filepath.Join(dir, DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	e, err = OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := e.DB().QueryRow("SELECT COUNT(*) FROM findings").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := e.Write(context.Background(), findings.Finding{Title: "must not write"}); err == nil {
		t.Fatal("read-only database accepted a write")
	}
	e.Close()
	after, err := os.ReadFile(filepath.Join(dir, DBFileName))
	if err != nil || string(before) != string(after) {
		t.Fatal("report opening changed database", err)
	}
}

func TestOpenReadOnlyDoesNotCreateMissingEngagement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if e, err := OpenReadOnly(dir); err == nil {
		e.Close()
		t.Fatal("missing engagement opened")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("read-only open created directory", err)
	}
}
