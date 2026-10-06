package kingfisher

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// parse accepts Kingfisher's sequence of JSON documents, including numeric
// summary findings counts. Mapping is exact: basename fallback is forbidden.
func parse(data []byte, paths map[string]Sample, redact bool) ([]Finding, []string) {
	out := []Finding{}
	warnings := []string{}
	warned := map[string]bool{}
	warn := func(s string) {
		if !warned[s] {
			warnings = append(warnings, s)
			warned[s] = true
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	for {
		var doc map[string]json.RawMessage
		err := d.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			warn("Malformed Kingfisher JSON; results may be incomplete.")
			break
		}
		raw := bytes.TrimSpace(doc["findings"])
		if len(raw) == 0 || raw[0] != '[' {
			continue
		}
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil {
			warn("Malformed Kingfisher findings; results may be incomplete.")
			continue
		}
		for _, row := range rows {
			if len(out) >= maxFindings {
				warn("Kingfisher finding limit reached; results are incomplete.")
				return out, warnings
			}
			var r struct {
				Rule struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rule"`
				Finding struct {
					Snippet    string `json:"snippet"`
					Path       string `json:"path"`
					Line       int    `json:"line"`
					Confidence string `json:"confidence"`
					Validation struct {
						Status string `json:"status"`
					} `json:"validation"`
				} `json:"finding"`
			}
			if json.Unmarshal(row, &r) != nil || r.Finding.Line < 0 || len(r.Finding.Snippet) > maxSampleBytes || len(r.Rule.ID) > 1024 || len(r.Rule.Name) > 4096 {
				warn("Malformed Kingfisher finding omitted.")
				continue
			}
			s, ok := paths[r.Finding.Path]
			if !ok {
				warn("Kingfisher finding with unmatched sample path omitted.")
				continue
			}
			severity := "high"
			if strings.EqualFold(r.Finding.Validation.Status, "valid") {
				severity = "critical"
			} else if strings.EqualFold(r.Finding.Confidence, "low") {
				severity = "medium"
			}
			snippet := r.Finding.Snippet
			if redact {
				snippet = redactSnippet(snippet)
			}
			region := s.Region
			if region == "" {
				region = "global"
			}
			out = append(out, Finding{SampleID: s.ID, Source: s.Source, Region: region, RuleID: r.Rule.ID, RuleName: r.Rule.Name, Snippet: snippet, Confidence: r.Finding.Confidence, Validation: r.Finding.Validation.Status, Severity: severity, Line: r.Finding.Line})
		}
	}
	return out, warnings
}

// Redaction suppresses the entire value, including short secrets.
func redactSnippet(s string) string {
	return "[REDACTED]"
}
