package kingfisher

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBinaryResolutionPATHAndFailClosed(t *testing.T) {
	missing := func(string) (string, error) { return "", exec.ErrNotFound }
	self := func() (string, error) { return filepath.Join(t.TempDir(), "gcpbuster"), nil }
	for _, tc := range []struct {
		name, path string
		err        error
		want       bool
	}{
		{"explicit", "/opt/trusted/kingfisher", nil, true},
		{"relative", "./kingfisher", nil, false},
		{"current_dir", "kingfisher", exec.ErrDot, false},
		{"permission", "", os.ErrPermission, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := resolveBinary(func(string) (string, error) { return tc.path, tc.err }, self)
			if (err == nil) != tc.want || (tc.want && p != tc.path) {
				t.Fatal("unexpected executable resolution")
			}
		})
	}
	if _, err := resolveBinary(missing, self); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing fallback accepted")
	}
	for _, f := range []func() (string, error){func() (string, error) { return "relative", nil }, func() (string, error) { return "", os.ErrPermission }} {
		if _, err := resolveBinary(missing, f); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid executable location accepted")
		}
	}
}

func TestPinnedBinaryVerifier(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kingfisher")
	body := []byte("trusted test bytes")
	if err := os.WriteFile(p, body, 0700); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if !verifiedBinary(p, digest) {
		t.Fatal("matching regular executable rejected")
	}
	if verifiedBinary(p, pinnedBinarySHA256) {
		t.Fatal("untrusted digest accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if verifiedBinary(link, digest) || verifiedBinary(dir, digest) {
		t.Fatal("nonregular executable accepted")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if verifiedBinary(p, digest) {
		t.Fatal("nonexecutable accepted")
	}
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, maxBinaryBytes+1); err != nil {
		t.Fatal(err)
	}
	if verifiedBinary(p, digest) {
		t.Fatal("oversized file accepted")
	}
}

func TestPinnedWorkspaceResolution(t *testing.T) {
	if os.Getenv("GCPBUSTER_KINGFISHER_SMOKE") != "1" {
		t.Skip("requires verified workspace release")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	p, err := resolveBinary(func(string) (string, error) { return "", exec.ErrNotFound }, func() (string, error) { return filepath.Join(root, "gcpbuster"), nil })
	if err != nil || p != filepath.Join(root, ".tools", pinnedVersion, "kingfisher") {
		t.Fatal("verified workspace fallback not resolved")
	}
}
