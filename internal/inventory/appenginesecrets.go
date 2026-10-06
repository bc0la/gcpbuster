package inventory

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

var appEngineSensitiveName = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|database_url|connection_string|jdbc)`)

// Preserve the existing configuration evaluator's BezosBuster name/value
// families as well as the shared content scanner's more specific patterns.
var appEngineCredentialPattern = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|-----BEGIN|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,}|gh[opsur]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,}|(?:password|passwd|secret|token|api_key)\s*[:=]\s*["']?[^\s"']{8,})`)
var appEngineSecretReference = regexp.MustCompile(`^(?://secretmanager\.googleapis\.com/)?projects/[A-Za-z0-9._:-]+/secrets/[A-Za-z0-9_-]+(?:/versions/[A-Za-z0-9_-]+)?$`)
var appEngineSecretPlaceholder = regexp.MustCompile(`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$SECRET[A-Za-z0-9_]*)$`)

// projectAppEngineSecrets inspects FULL version environment maps transiently.
// Digests identify variable names, never credential values. No input text is
// returned in candidates or errors. Limits bound work, not cloud permissions.
func projectAppEngineSecrets(raw Object) ([]any, error) {
	var out []any
	partial := false
	remaining := 4 << 20
	for _, field := range []string{"envVariables", "buildEnvVariables"} {
		v, exists := raw[field]
		if !exists {
			continue
		}
		values := Obj(v)
		if values == nil {
			partial = true
			continue
		}
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, name := range keys {
			value, ok := values[name].(string)
			if !ok {
				partial = true
				continue
			}
			if len(name) > remaining || len(value) > remaining-len(name) {
				return out, fmt.Errorf("App Engine environment inspection byte limit reached")
			}
			remaining -= len(name) + len(value)
			value = strings.TrimSpace(value)
			if value == "" || value == "[REDACTED]" || value == "true" || value == "false" || appEngineSecretReference.MatchString(value) || appEngineSecretPlaceholder.MatchString(value) {
				continue
			}
			rules := map[string]bool{}
			if appEngineSensitiveName.MatchString(name) {
				rules["sensitive_variable_name"] = true
			}
			for _, match := range secretmatch.Text([]byte(value), "") {
				rules[match.Rule] = true
			}
			if len(rules) == 0 && appEngineCredentialPattern.MatchString(value) {
				rules["credential_pattern"] = true
			}
			ordered := make([]string, 0, len(rules))
			for rule := range rules {
				ordered = append(ordered, rule)
			}
			sort.Strings(ordered)
			for _, rule := range ordered {
				if len(out) >= 1000 {
					return out, fmt.Errorf("App Engine environment candidate limit reached")
				}
				out = append(out, Object{"field": field, "name_digest": fmt.Sprintf("%x", sha256.Sum256([]byte(name))), "rule": rule})
			}
		}
	}
	if partial {
		return out, fmt.Errorf("some App Engine environment fields were malformed")
	}
	return out, nil
}
