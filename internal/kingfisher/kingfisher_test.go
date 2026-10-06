package kingfisher

import (
	"context"
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/testfixture"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMultiDocumentSeverityValuesAndRedaction(t *testing.T) {
	data := []byte(`{"findings":[{"rule":{"id":"aws","name":"AWS"},"finding":{"path":"sample","snippet":"SENSITIVE_VALUE_12345","line":3,"confidence":"low","validation":{"status":"invalid"}}},{"finding":{"path":"sample","snippet":"valid-secret","validation":{"status":"valid"}}}]} {"findings":2,"rules_run":42}`)
	paths := map[string]Sample{"sample": {ID: "stable-id", Source: "cloudrun/config"}}
	f, w := parse(data, paths, false)
	if len(w) != 0 || len(f) != 2 || f[0].Snippet != "SENSITIVE_VALUE_12345" || f[0].Severity != "medium" || f[1].Severity != "critical" || f[0].Region != "global" || f[0].SampleID != "stable-id" {
		t.Fatalf("unexpected parsed metadata, count=%d warnings=%d", len(f), len(w))
	}
	f, _ = parse(data, paths, true)
	if f[0].Snippet != "[REDACTED]" {
		t.Fatal("redaction mismatch")
	}
	b, _ := json.Marshal(f)
	for _, fragment := range []string{"SENSITIVE", "2345", "valid-secret"} {
		if strings.Contains(string(b), fragment) {
			t.Fatal("redacted output leaks secret fragments")
		}
	}
}

func TestParseMalformedAndUnmappedNeverLeakWarnings(t *testing.T) {
	data := []byte(`{"findings":[{"finding":{"path":"/outside/sample","snippet":"SECRET_SENTINEL"}},{"finding":{"path":"sample","snippet":"ok"}}]} SECRET_SENTINEL`)
	f, w := parse(data, map[string]Sample{"sample": {ID: "id"}}, false)
	if len(f) != 1 || len(w) != 2 || strings.Contains(strings.Join(w, " "), "SECRET_SENTINEL") {
		t.Fatal("unsafe or incomplete parser result")
	}
}

func fakeBinary(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kingfisher")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunFixedArgumentsPrivateStagingScrubbedEnvironmentCleanup(t *testing.T) {
	t.Setenv("KINGFISHER_ALERT_REPORT_URL", "SECRET_SENTINEL")
	t.Setenv("HTTPS_PROXY", "SECRET_SENTINEL")
	marker := filepath.Join(t.TempDir(), "staging-path")
	quoted, _ := json.Marshal(marker)
	binary := fakeBinary(t, `[ "$1" = scan ] || exit 2
[ "$4" = json ] || exit 2
case "$*" in *--no-validate*--no-update-check*--no-extract-archives*--no-rule-cache*) ;; *) exit 2;; esac
[ -z "$KINGFISHER_ALERT_REPORT_URL$HTTPS_PROXY" ] || exit 2
[ "$(/usr/bin/stat -c %a "$2")" = 700 ] || exit 2
for p in "$2"/*.txt; do
[ "$(/usr/bin/stat -c %a "$p")" = 600 ] || exit 2
printf '{"findings":[{"rule":{"id":"test"},"finding":{"path":"%s","snippet":"FULL_SECRET_SENTINEL","confidence":"high"}}]}\n' "$p"
done
printf '%s' "$2" > `+string(quoted)+`
exit 200
`)
	r, err := run(context.Background(), binary, []Sample{{ID: "../not-a-filename", Content: "secret", Source: "sample"}}, Options{})
	if err != nil || len(r.Findings) != 1 || r.Findings[0].Snippet != "FULL_SECRET_SENTINEL" || r.ExitCode != 200 {
		t.Fatalf("runner failed: %v", err)
	}
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(string(b)); !os.IsNotExist(err) {
		t.Fatal("staging directory not removed")
	}
}

func TestRunTimeoutFailureAndBoundsSanitized(t *testing.T) {
	samples := []Sample{{ID: "one", Content: "x"}}
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
	}{
		{"failure", "echo SECRET_SENTINEL >&2; exit 9", time.Second},
		{"timeout", "exec /bin/sleep 30", 20 * time.Millisecond},
		{"stderr_limit", "/usr/bin/head -c 70000 /dev/zero >&2; exit 0", time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(context.Background(), fakeBinary(t, tc.script), samples, Options{Timeout: tc.timeout})
			if err == nil || strings.Contains(err.Error(), "SECRET_SENTINEL") {
				t.Fatal("missing sanitized failure")
			}
		})
	}
	_, err := run(context.Background(), "/not/executed", []Sample{{ID: "same"}, {ID: "same"}}, Options{})
	if err == nil {
		t.Fatal("duplicate IDs accepted")
	}
	_, err = run(context.Background(), "/not/executed", []Sample{{ID: "id", Content: strings.Repeat("x", maxSampleBytes+1)}}, Options{})
	if err == nil {
		t.Fatal("oversized sample accepted")
	}
}

func TestBoundedOutputAndFindingLimit(t *testing.T) {
	canceled := false
	w := boundedOutput{limit: 4, cancel: func() { canceled = true }}
	w.Write([]byte("SECRET"))
	if !canceled || !w.overflow || w.buf.Len() != 4 {
		t.Fatal("output unbounded")
	}
	row := `{"finding":{"path":"sample","snippet":"x"}}`
	data := []byte(`{"findings":[` + strings.Repeat(row+",", maxFindings) + row + `]}`)
	f, warnings := parse(data, map[string]Sample{"sample": {ID: "id"}}, false)
	if len(f) != maxFindings || len(warnings) != 1 {
		t.Fatal("finding limit not applied")
	}
}

// Opt-in integration test uses only a synthetic, never-issued credential and
// the separately digest-verified official release in the workspace tools dir.
func TestOfficialKingfisherSmoke(t *testing.T) {
	if os.Getenv("GCPBUSTER_KINGFISHER_SMOKE") != "1" {
		t.Skip("requires verified workspace release")
	}
	binary, err := exec.LookPath("kingfisher")
	if err != nil {
		binary, err = filepath.Abs("../../.tools/kingfisher-v1.112.0/kingfisher")
		if err != nil {
			t.Fatal(err)
		}
	}
	if !verifiedBinary(binary, pinnedBinarySHA256) {
		t.Fatal("smoke test requires the digest-verified pinned Kingfisher release")
	}
	// Generated synthetic format fixture, never issued or validated.
	fake := testfixture.GitHubToken()
	samples := []Sample{{ID: "synthetic-only", Source: "test/config", Content: "github_token = \"" + fake + "\"\n"}}
	report, err := run(context.Background(), binary, samples, Options{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 || len(report.Warnings) != 0 {
		t.Fatalf("expected parsed synthetic finding; count=%d warnings=%d exit=%d", len(report.Findings), len(report.Warnings), report.ExitCode)
	}
	matched := false
	for _, f := range report.Findings {
		if strings.Contains(f.Snippet, fake) {
			matched = true
		}
	}
	if !matched {
		t.Fatal("full synthetic value absent")
	}
	report, err = run(context.Background(), binary, samples, Options{Redact: true, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(report)
	if len(report.Findings) == 0 || strings.Contains(string(b), fake) || strings.Contains(string(b), fake[4:10]) || strings.Contains(string(b), fake[len(fake)-6:]) {
		t.Fatal("redacted smoke result leaked value")
	}
}
