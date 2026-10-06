package kingfisher

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const pinnedVersion = "kingfisher-v1.112.0"
const pinnedBinarySHA256 = "8dc3d3d2c4ad4b12b3099efd3fb09bf14013a749d733bf1c0b62008622511c16"
const maxBinaryBytes = 128 << 20

// Explicit user PATH installations retain precedence. Only an absent PATH
// installation enables the fixed, digest-pinned executable-relative fallback.
func resolveBinary(lookPath func(string) (string, error), executable func() (string, error)) (string, error) {
	p, err := lookPath("kingfisher")
	if err == nil {
		if filepath.IsAbs(p) {
			return p, nil
		}
		return "", ErrUnavailable
	}
	if !errors.Is(err, exec.ErrNotFound) {
		return "", ErrUnavailable
	}
	self, err := executable()
	if err != nil || !filepath.IsAbs(self) {
		return "", ErrUnavailable
	}
	p = filepath.Join(filepath.Dir(self), ".tools", pinnedVersion, "kingfisher")
	if !verifiedBinary(p, pinnedBinarySHA256) {
		return "", ErrUnavailable
	}
	return p, nil
}

func verifiedBinary(path, digest string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > maxBinaryBytes {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1))
	return err == nil && n == info.Size() && fmt.Sprintf("%x", h.Sum(nil)) == digest
}
