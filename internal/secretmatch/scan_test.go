package secretmatch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestTarGzipInspectionAndLimits(t *testing.T) {
	var plain bytes.Buffer
	w := tar.NewWriter(&plain)
	content := "password=TAR_VALUE_NOT_SAVED"
	for _, name := range []string{"../../config.env", "second.txt"} {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(plain.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name string
		data []byte
	}{{"source.tar", plain.Bytes()}, {"unnamed-source", compressed.Bytes()}} {
		hits, err := Scan(context.Background(), sample.name, sample.data, 8192, 10)
		if err != nil || len(hits) != 2 {
			t.Fatal(hits, err)
		}
		if _, err := Scan(context.Background(), sample.name, sample.data, 100, 10); err == nil {
			t.Fatal("expansion cap ignored")
		}
		if _, err := Scan(context.Background(), sample.name, sample.data, 8192, 1); err == nil {
			t.Fatal("entry cap ignored")
		}
	}
	broken := compressed.Bytes()[:compressed.Len()-4]
	if _, err := Scan(context.Background(), "source.tgz", broken, 8192, 10); err == nil {
		t.Fatal("truncated gzip accepted")
	}
	if hits, err := Scan(context.Background(), "no-extension", archive(t, map[string]string{"config.env": content}), 8192, 10); err != nil || len(hits) != 1 {
		t.Fatal("ZIP magic detection", hits, err)
	}
}

func archive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestTextDetectionAndValueRedaction(t *testing.T) {
	text := "safe text\npassword=DO_NOT_PERSIST_THIS\n{\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nexample\"}\npostgres://app:VERY_SECRET_PASSWORD@db.invalid/x\n"
	hits := Text([]byte(text), "config.env")
	if len(hits) < 3 {
		t.Fatal(hits)
	}
	data, _ := json.Marshal(hits)
	for _, secret := range []string{"DO_NOT_PERSIST_THIS", "VERY_SECRET_PASSWORD", "BEGIN PRIVATE KEY"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("value leaked: %s", data)
		}
	}
	found := false
	for _, h := range hits {
		if h.Rule == "credential_assignment" && h.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("incorrect source line", hits)
	}
	if got := Text([]byte("\x00password=SECRET_VALUE"), ""); len(got) != 0 {
		t.Fatal("binary sample scanned as text")
	}
}
func TestArchiveInspectionAndLimits(t *testing.T) {
	b := archive(t, map[string]string{"../../config.env": "password=ARCHIVE_SECRET_VALUE"})
	hits, err := Scan(context.Background(), "source.zip", b, 4096, 10)
	if err != nil || len(hits) != 1 || hits[0].File != "../../config.env" {
		t.Fatalf("%+v %v", hits, err)
	}
	// The path is only evidence: no extraction or filesystem writes occur.
	if _, err := Scan(context.Background(), "source.zip", b, 4, 10); err == nil {
		t.Fatal("expansion cap ignored")
	}
	b = archive(t, map[string]string{"one.txt": "plain", "two.txt": "plain"})
	if _, err := Scan(context.Background(), "source.zip", b, 4096, 1); err == nil {
		t.Fatal("entry cap ignored")
	}
	if _, err := Scan(context.Background(), "source.zip", []byte("broken"), 4096, 10); err == nil {
		t.Fatal("invalid ZIP treated as inspected")
	}
	if _, err := Scan(context.Background(), "source.zip", archive(t, map[string]string{"nested.zip": "fake"}), 4096, 10); err == nil {
		t.Fatal("nested ZIP silently skipped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, "source.zip", b, 4096, 10); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestSupportedFormats(t *testing.T) {
	for _, name := range []string{".env", "state.tfstate", "lambda.zip", "secret.pem", "Dockerfile", "config.yml"} {
		if !Supported(name, "") {
			t.Error(name)
		}
	}
	if Supported("photo.jpg", "image/jpeg") {
		t.Fatal("unexpected binary format")
	}
	if !Supported("unknown.extension", "text/plain") {
		t.Fatal("text content-type ignored")
	}
	if Supported("binary", strings.Repeat("x", 20)) {
		t.Fatal("unknown binary format")
	}
}
