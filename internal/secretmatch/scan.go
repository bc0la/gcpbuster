// Package secretmatch detects credential candidates without returning values,
// snippets or hashes of the matched secret. It never validates credentials.
package secretmatch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

type Match struct {
	Rule string `json:"rule"`
	Line int    `json:"line"`
	File string `json:"file,omitempty"`
}

var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"google_oauth_access_token", regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`)},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b`)},
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`)},
	{"credential_assignment", regexp.MustCompile(`(?i)(?:password|passwd|secret|access[_-]?token|refresh[_-]?token|api[_-]?key)["']?\s*[:=]\s*["']?[^\s"'<>]{8,}`)},
	{"url_credentials", regexp.MustCompile(`(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]{4,}@`)},
}

func Text(data []byte, file string) []Match {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	var out []Match
	for _, p := range patterns {
		seen := map[int]bool{}
		line, previous := 1, 0
		for _, loc := range p.re.FindAllIndex(data, -1) {
			line += bytes.Count(data[previous:loc[0]], []byte{'\n'})
			previous = loc[0]
			if p.name == "credential_assignment" {
				match := string(data[loc[0]:loc[1]])
				if i := strings.IndexAny(match, ":="); i >= 0 {
					value := strings.Trim(strings.TrimSpace(match[i+1:]), "\"'")
					if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "{{") || strings.HasPrefix(value, "$env:") || strings.Contains(value, "/secrets/") {
						continue
					}
				}
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, Match{p.name, line, file})
		}
	}
	return out
}

// Supported limits content collection to common text/config/source and ZIP/TAR
// artifacts. Unsupported formats are explicitly counted by the collector.
func Supported(name, contentType string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar") {
		return true
	}
	base := path.Base(lower)
	if strings.HasPrefix(strings.ToLower(contentType), "text/") {
		return true
	}
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc", "dockerfile", "credentials", "config", "id_rsa", "id_ed25519":
		return true
	}
	switch path.Ext(lower) {
	case ".zip", ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".tf", ".tfvars", ".tfstate", ".hcl", ".sql", ".txt", ".log", ".md", ".csv", ".html", ".htm", ".pem", ".key", ".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".cs", ".sh", ".bash", ".ps1":
		return true
	}
	return false
}

// Scan inspects text, ZIP, TAR or gzip-compressed TAR without extracting to disk.
// Archive limits cover total decompressed bytes AND entries, preventing bombs.
func Scan(ctx context.Context, name string, data []byte, maxExpanded int64, maxEntries int) ([]Match, error) {
	if maxExpanded <= 0 || maxEntries <= 0 {
		return nil, fmt.Errorf("positive archive limits required")
	}
	if bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) || bytes.HasPrefix(data, []byte{'P', 'K', 5, 6}) {
		name = "detected.zip"
	} else if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		name = "detected.tar.gz"
	}
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar") {
		return scanTar(ctx, name, data, maxExpanded, maxEntries)
	}
	if !strings.EqualFold(path.Ext(name), ".zip") {
		if bytes.IndexByte(data, 0) >= 0 {
			return nil, fmt.Errorf("binary content not inspected as text")
		}
		return Text(data, ""), ctx.Err()
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid or incomplete ZIP archive")
	}
	var out []Match
	remaining := maxExpanded
	for i, f := range z.File {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if i >= maxEntries {
			return out, fmt.Errorf("archive entry limit reached (%d)", maxEntries)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if !Supported(f.Name, "") {
			continue
		}
		if archiveName(f.Name) {
			return out, fmt.Errorf("nested archive not inspected")
		}
		if f.UncompressedSize64 > uint64(remaining) {
			return out, fmt.Errorf("archive expansion limit reached (%d bytes)", maxExpanded)
		}
		r, err := f.Open()
		if err != nil {
			return out, fmt.Errorf("cannot open ZIP entry")
		}
		b, readErr := io.ReadAll(io.LimitReader(r, remaining+1))
		r.Close()
		if readErr != nil {
			return out, fmt.Errorf("cannot read ZIP entry")
		}
		if int64(len(b)) > remaining {
			return out, fmt.Errorf("archive expansion limit reached (%d bytes)", maxExpanded)
		}
		remaining -= int64(len(b))
		out = append(out, Text(b, f.Name)...)
	}
	return out, nil
}

func archiveName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

func scanTar(ctx context.Context, name string, data []byte, maxExpanded int64, maxEntries int) ([]Match, error) {
	var input io.Reader = bytes.NewReader(data)
	if !strings.HasSuffix(strings.ToLower(name), ".tar") {
		gz, err := gzip.NewReader(input)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip source archive")
		}
		defer gz.Close()
		input = gz
	}
	limited := &io.LimitedReader{R: input, N: maxExpanded + 1}
	tr := tar.NewReader(limited)
	var out []Match
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			_, tailErr := io.Copy(io.Discard, limited)
			if limited.N <= 0 {
				return out, fmt.Errorf("archive expansion limit reached (%d bytes)", maxExpanded)
			}
			if tailErr != nil {
				return out, fmt.Errorf("invalid archive trailer")
			}
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("invalid, truncated or oversized tar archive")
		}
		if count >= maxEntries {
			return out, fmt.Errorf("archive entry limit reached (%d)", maxEntries)
		}
		if h.Typeflag != tar.TypeReg || !Supported(h.Name, "") {
			continue
		}
		lower := strings.ToLower(h.Name)
		if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar") {
			return out, fmt.Errorf("nested archive not inspected")
		}
		if h.Size > maxExpanded {
			return out, fmt.Errorf("archive expansion limit reached (%d bytes)", maxExpanded)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return out, fmt.Errorf("cannot read tar entry within expansion limit")
		}
		out = append(out, Text(b, h.Name)...)
	}
}
