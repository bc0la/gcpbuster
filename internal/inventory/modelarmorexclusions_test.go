package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestModelArmorExclusionLiteralProjection(t *testing.T) {
	for _, tc := range []struct {
		pattern, scope string
		want           int
	}{{"(?s).*", "MATCHING_SCOPE_PARTIAL_MATCH", 1}, {"(?s)^.*$", "MATCHING_SCOPE_PARTIAL_MATCH", 1}, {".*", "MATCHING_SCOPE_PARTIAL_MATCH", 0}, {"(?s).*", "MATCHING_SCOPE_FULL_MATCH", 0}, {"(?s).*", "", 0}, {"SENSITIVE_SENTINEL", "MATCHING_SCOPE_PARTIAL_MATCH", 0}} {
		ex := Object{"regex": Object{"pattern": tc.pattern}}
		if tc.scope != "" {
			ex["matchingScope"] = tc.scope
		}
		raw := Object{"ruleSets": []any{Object{"filterTypes": []any{"RESPONSIBLE_AI"}, "rules": []any{Object{"exclusionRule": ex}}}}}
		got := projectModelArmorExclusions(raw)
		if got["complete"] != true || len(List(got["rules"])) != tc.want {
			t.Fatal(got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SENSITIVE_SENTINEL") || strings.Contains(string(b), "(?s)") {
			t.Fatal("pattern retained")
		}
	}
}
func TestModelArmorExclusionMalformedUnionAndTypedFlags(t *testing.T) {
	for _, ex := range []Object{{"regex": Object{"pattern": "(?s).*"}, "dictionary": Object{"wordList": []any{"SENSITIVE_SENTINEL"}}}, {"regex": Object{"pattern": true}}, {"regex": Object{"pattern": "(?s).*"}, "condition": "SENSITIVE_SENTINEL"}, {"dictionary": nil}, {"regex": Object{"pattern": "(?s).*"}, "matchingScope": false}} {
		raw := Object{"ruleSets": []any{Object{"filterTypes": []any{"PROMPT_INJECTION_AND_JAILBREAK"}, "rules": []any{Object{"exclusionRule": ex}}}}}
		got := projectModelArmorExclusions(raw)
		if got["complete"] != false || len(List(got["rules"])) != 0 {
			t.Fatal(got)
		}
		safe, e := projectViewerModelArmor(Object{"filterConfig": Object{"filterRuleSettings": raw}})
		if e == nil || safe["projection_complete"] != false {
			t.Fatal(safe, e)
		}
	}
}

func TestModelArmorExclusionBudgets(t *testing.T) {
	makeRule := func(pattern string) any {
		return Object{"exclusionRule": Object{"matchingScope": "MATCHING_SCOPE_PARTIAL_MATCH", "regex": Object{"pattern": pattern}}}
	}
	for _, mode := range []string{"rules", "bytes", "pattern"} {
		rules := []any{}
		switch mode {
		case "rules":
			for i := 0; i < 1001; i++ {
				rules = append(rules, makeRule("(?s).*"))
			}
		case "bytes":
			for i := 0; i < 300; i++ {
				rules = append(rules, makeRule(strings.Repeat("x", 4000)))
			}
		case "pattern":
			rules = append(rules, makeRule(strings.Repeat("x", 4001)))
		}
		got := projectModelArmorExclusions(Object{"ruleSets": []any{Object{"filterTypes": []any{"RESPONSIBLE_AI"}, "rules": rules}}})
		if got["complete"] != false {
			t.Fatal(mode, got)
		}
	}
}
