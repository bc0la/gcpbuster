package engagement

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPrecreatesPrivateDatabaseAndPreservesResume(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private?mode=memory#literal")
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, filepath.Join(dir, DBFileName)} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if path == dir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("unexpected mode", info.Mode())
		}
	}
	if err := e.SetMeta(context.Background(), "sentinel", "resume-preserved"); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	v, exists, err := e.GetMeta(context.Background(), "sentinel")
	if err != nil || !exists || v != "resume-preserved" {
		t.Fatal(v, exists, err)
	}
}

func TestOpenRejectsUnprivateOrLinkedDestinationsWithoutMutation(t *testing.T) {
	for _, kind := range []string{"directory-permissions", "directory-symlink", "database-permissions", "database-symlink", "database-directory", "wal-symlink", "journal-permissions"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "engagement")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(base, "outside")
			sentinel := []byte("not-a-database-sentinel")
			if err := os.WriteFile(target, sentinel, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory-permissions":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				link := filepath.Join(base, "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "database-permissions":
				if err := os.WriteFile(filepath.Join(dir, DBFileName), sentinel, 0644); err != nil {
					t.Fatal(err)
				}
			case "database-symlink":
				if err := os.Symlink(target, filepath.Join(dir, DBFileName)); err != nil {
					t.Fatal(err)
				}
			case "database-directory":
				if err := os.Mkdir(filepath.Join(dir, DBFileName), 0700); err != nil {
					t.Fatal(err)
				}
			case "wal-symlink":
				if err := os.Symlink(target, filepath.Join(dir, DBFileName+"-wal")); err != nil {
					t.Fatal(err)
				}
			case "journal-permissions":
				if err := os.WriteFile(filepath.Join(dir, DBFileName+"-journal"), sentinel, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if e, err := Open(dir); err == nil {
				e.Close()
				t.Fatal("accepted unsafe engagement")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != string(sentinel) {
				t.Fatal("outside target changed", err)
			}
			if kind == "database-permissions" {
				data, err := os.ReadFile(filepath.Join(dir, DBFileName))
				if err != nil || string(data) != string(sentinel) {
					t.Fatal("existing database changed", err)
				}
			}
		})
	}
}

func TestOpenRejectsUnprotectedWritableOrSymlinkAncestor(t *testing.T) {
	for _, kind := range []string{"writable", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "writable" {
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			} else {
				link := filepath.Join(base, "link")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				parent = link
			}
			if e, err := Open(filepath.Join(parent, "new-engagement")); err == nil {
				e.Close()
				t.Fatal("unsafe ancestor accepted")
			}
			if _, err := os.Lstat(filepath.Join(parent, "new-engagement")); !os.IsNotExist(err) {
				t.Fatal("unsafe ancestor modified", err)
			}
		})
	}
}
