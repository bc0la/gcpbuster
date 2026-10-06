package engagement

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
)

const SecretArtifactMaxBytes = 32 << 20

var secretArtifactPath = regexp.MustCompile(`^secret-hits/[a-f0-9]{32}\.txt$`)

func ValidSecretArtifactPath(relative string) bool { return secretArtifactPath.MatchString(relative) }

// secretRoot rejects link-shaped roots and pins descriptor-relative access to
// the private artifact directory. Errors deliberately omit paths and contents.
func (e *Engagement) secretRoot(create bool) (*os.Root, error) {
	info, err := os.Lstat(e.Dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid engagement directory")
	}
	root, err := os.OpenRoot(e.Dir)
	if err != nil {
		return nil, errors.New("cannot open engagement directory")
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("engagement directory changed")
	}
	if create {
		if err := root.Mkdir("secret-hits", 0700); err != nil && !os.IsExist(err) {
			return nil, errors.New("cannot create secret artifact directory")
		}
	}
	info, err = root.Lstat("secret-hits")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, errors.New("secret artifact directory must be private and not a symlink")
	}
	dir, err := root.OpenRoot("secret-hits")
	if err != nil {
		return nil, errors.New("cannot open secret artifact directory")
	}
	opened, err = dir.Stat(".")
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm() != 0700 {
		dir.Close()
		return nil, errors.New("secret artifact directory changed")
	}
	return dir, nil
}

// WriteSecretArtifact persists a bounded raw candidate for manual inspection.
// It never validates credentials. Callers must not call this in redacted mode.
func (e *Engagement) WriteSecretArtifact(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > SecretArtifactMaxBytes {
		return "", errors.New("invalid secret artifact size")
	}
	dir, err := e.secretRoot(true)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("cannot generate secret artifact identifier")
	}
	name := hex.EncodeToString(nonce[:]) + ".txt"
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot create secret artifact")
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = dir.Remove(name)
		}
	}()
	if _, err = f.Write(payload); err != nil {
		return "", errors.New("cannot write secret artifact")
	}
	if err = f.Sync(); err != nil {
		return "", errors.New("cannot sync secret artifact")
	}
	if err = f.Close(); err != nil {
		return "", errors.New("cannot close secret artifact")
	}
	ok = true
	return "secret-hits/" + name, nil
}

func (e *Engagement) OpenSecretArtifact(relative string) (*os.File, error) {
	if !ValidSecretArtifactPath(relative) {
		return nil, errors.New("invalid secret artifact reference")
	}
	dir, err := e.secretRoot(false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	name := relative[len("secret-hits/"):]
	before, err := dir.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > SecretArtifactMaxBytes {
		return nil, errors.New("invalid secret artifact file")
	}
	f, err := dir.Open(name)
	if err != nil {
		return nil, errors.New("cannot open secret artifact")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0600 || after.Size() > SecretArtifactMaxBytes {
		f.Close()
		return nil, errors.New("secret artifact changed")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, errors.New("cannot read secret artifact")
	}
	return f, nil
}
