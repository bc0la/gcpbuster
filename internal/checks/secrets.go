package checks

import (
	"fmt"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

// Keep the local BezosBuster lambda_env name/value families, including its
// intentionally broad PEM/Slack/JWT prefix heuristics, alongside GCP patterns.
// These are candidate indicators, not credential validity or detector parity
// with an external scanner. Structured secret references remain excluded.
var secretName = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|database_url|connection_string|jdbc)`)
var secretValue = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|-----BEGIN|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,}|gh[opsur]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,}|(?:password|passwd|secret|token|api_key)\s*[:=]\s*["']?[^\s"']{8,})`)
var secretReference = regexp.MustCompile(`^(?://secretmanager\.googleapis\.com/)?projects/[A-Za-z0-9._:-]+/(?:locations/[a-z][a-z0-9-]*/)?secrets/[A-Za-z0-9_-]+(?:/versions/[A-Za-z0-9_-]+)?$`)
var secretPlaceholder = regexp.MustCompile(`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{secure\([^(){}\r\n]+\)\}|\$SECRET[A-Za-z0-9_]*)$`)
var secretNameDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var secretEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Only paths and classification are retained. Even short matches are redacted.
func configurationSecrets(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	seen := map[string]bool{}
	if a.Type == "appengine.googleapis.com/Version" {
		for _, raw := range arr(a.Resource.Data["_gcpbusterSecretCandidates"]) {
			d := obj(raw)
			field, digest, rule := s(d["field"]), s(d["name_digest"]), s(d["rule"])
			if (field != "envVariables" && field != "buildEnvVariables") || !secretNameDigest.MatchString(digest) {
				continue
			}
			switch rule {
			case "sensitive_variable_name", "credential_pattern", "private_key", "google_api_key", "google_oauth_access_token", "github_token", "aws_access_key_id", "slack_token", "credential_assignment", "url_credentials":
			default:
				continue
			}
			key := field + ":" + digest + ":" + rule
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Result{"high", "Potential plaintext secret in resource configuration", inventory.Object{"field": field, "name_digest": digest, "rule": rule, "value": "[REDACTED]", "assessment": "heuristic candidate; not a validated credential"}, "Inspect the environment configuration securely, rotate exposed credentials, and replace plaintext with managed secret references."})
		}
	}
	add := func(path, kind string) {
		if !seen[path] {
			seen[path] = true
			out = append(out, Result{"high", "Potential plaintext secret in resource configuration", inventory.Object{"field": path, "kind": kind, "value": "[REDACTED]", "assessment": "heuristic candidate; not a validated credential"}, "Inspect the field securely, rotate any exposed credential, and replace plaintext with a managed secret reference."})
		}
	}
	var walk func(any, string, int)
	walk = func(v any, path string, depth int) {
		if depth > 80 {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			// Kubernetes-style env and Compute metadata use name/key + value.
			name := s(x["name"])
			if name == "" {
				name = s(x["key"])
			}
			if secretName.MatchString(name) && candidate(s(x["value"])) {
				add(path+".value", "sensitive variable name")
			}
			for _, k := range sortedKeys(x) {
				if strings.HasPrefix(k, "_gcpbuster") {
					continue
				}
				// Secret references identify protected values; they aren't plaintext.
				lower := strings.ToLower(k)
				if lower == "secretkeyref" || lower == "secretversion" || lower == "secretenvironmentvariables" || lower == "secretvolumes" || lower == "availablesecrets" || lower == "valuefrom" || lower == "valuesource" {
					continue
				}
				p := path + "." + k
				if secretName.MatchString(k) && candidate(s(x[k])) {
					add(p, "sensitive field name")
				}
				walk(x[k], p, depth+1)
			}
		case []any:
			for i, e := range x {
				walk(e, fmt.Sprintf("%s[%d]", path, i), depth+1)
			}
		case string:
			// Cloud Build steps store native environment entries as NAME=value,
			// unlike Run's name/value objects and Functions' keyed maps.
			if name, value, ok := strings.Cut(x, "="); ok && secretEnvironmentName.MatchString(name) {
				if !candidate(value) {
					return
				}
				if secretName.MatchString(name) {
					add(path, "sensitive environment assignment")
				}
			}
			if candidate(x) && secretValue.MatchString(x) {
				add(path, "credential pattern")
			}
		}
	}
	walk(a.Resource.Data, "resource.data", 0)
	return out
}
func candidate(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v == "[REDACTED]" || secretPlaceholder.MatchString(v) || secretReference.MatchString(v) || v == "true" || v == "false" {
		return false
	}
	return true
}
