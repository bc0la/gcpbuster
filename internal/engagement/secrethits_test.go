package engagement

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretArtifactPrivateOpaqueRoundTrip(t *testing.T) {
	e := &Engagement{Dir: t.TempDir()}
	value := []byte("synthetic-secret-<script>not-validated</script>\n")
	path, err := e.WriteSecretArtifact(value)
	if err != nil || !ValidSecretArtifactPath(path) || strings.Contains(path, "synthetic") {
		t.Fatal(path, err)
	}
	for name, mode := range map[string]os.FileMode{"secret-hits": 0700, path: 0600} {
		st, err := os.Stat(filepath.Join(e.Dir, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatal(st, err)
		}
	}
	f, err := e.OpenSecretArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != string(value) {
		t.Fatal("not exact")
	}
	other, err := e.WriteSecretArtifact(value)
	if err != nil || other == path {
		t.Fatal(other, err)
	}
}

func TestSecretArtifactRejectsLinksModesBoundsAndPaths(t *testing.T) {
	e := &Engagement{Dir: t.TempDir()}
	for _, path := range []string{"../engagement.db", "secret-hits/../engagement.db", "secret-hits/", "/secret-hits/" + strings.Repeat("a", 32) + ".txt", "secret-hits/" + strings.Repeat("a", 32) + ".json"} {
		if _, err := e.OpenSecretArtifact(path); err == nil {
			t.Fatal(path)
		}
	}
	if _, err := e.WriteSecretArtifact(make([]byte, SecretArtifactMaxBytes+1)); err == nil {
		t.Fatal("bound")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(e.Dir, "secret-hits")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteSecretArtifact([]byte("sensitive")); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.Dir, "secret-hits")); err != nil {
		t.Fatal(err)
	}
	path, err := e.WriteSecretArtifact([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(e.Dir, path), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.OpenSecretArtifact(path); err == nil {
		t.Fatal("permissive file")
	}
	if err := os.Remove(filepath.Join(e.Dir, path)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "anything"), filepath.Join(e.Dir, path)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.OpenSecretArtifact(path); err == nil {
		t.Fatal("symlink")
	}
}
