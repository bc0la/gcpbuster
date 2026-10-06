package inventory

// projectModelArmorExclusions recognizes only two literal patterns. It never
// compiles regex, reads dictionary contents semantically, or preserves source.
func projectModelArmorExclusions(raw any) Object {
	out := Object{"complete": true, "rules": []any{}}
	fail := func() { out["complete"] = false }
	m, ok := raw.(map[string]any)
	if !ok {
		fail()
		return out
	}
	for k := range m {
		if k != "ruleSets" {
			fail()
			return out
		}
	}
	rows, exists := m["ruleSets"]
	if !exists {
		return out
	}
	sets, ok := rows.([]any)
	if !ok || len(sets) > 1000 {
		fail()
		return out
	}
	candidates := []any{}
	totalRules, totalBytes := 0, 0
	for si, raw := range sets {
		set, ok := raw.(map[string]any)
		if !ok {
			fail()
			continue
		}
		valid := true
		for k := range set {
			if k != "filterTypes" && k != "rules" {
				valid = false
			}
		}
		types, ok := set["filterTypes"].([]any)
		if !ok || len(types) == 0 || len(types) > 2 {
			valid = false
		}
		cleanTypes := []any{}
		seen := map[string]bool{}
		for _, v := range types {
			s, ok := v.(string)
			if !ok || (s != "PROMPT_INJECTION_AND_JAILBREAK" && s != "RESPONSIBLE_AI") || seen[s] {
				valid = false
			} else {
				seen[s] = true
				cleanTypes = append(cleanTypes, s)
			}
		}
		rules, ok := set["rules"].([]any)
		if !ok || len(rules) == 0 || len(rules) > 1000 {
			valid = false
		}
		if !valid {
			fail()
			continue
		}
		for ri, raw := range rules {
			totalRules++
			if totalRules > 1000 {
				fail()
				out["rules"] = candidates
				return out
			}
			rule, ok := raw.(map[string]any)
			if !ok || len(rule) != 1 {
				fail()
				continue
			}
			ex, ok := rule["exclusionRule"].(map[string]any)
			if !ok {
				fail()
				continue
			}
			valid = true
			for k := range ex {
				if k != "matchingScope" && k != "regex" && k != "dictionary" {
					valid = false
				}
			}
			scope := ""
			if v, exists := ex["matchingScope"]; exists {
				s, ok := v.(string)
				if !ok || (s != "MATCHING_SCOPE_UNSPECIFIED" && s != "MATCHING_SCOPE_FULL_MATCH" && s != "MATCHING_SCOPE_PARTIAL_MATCH") {
					valid = false
				} else {
					scope = s
				}
			}
			_, rx := ex["regex"]
			_, dict := ex["dictionary"]
			if rx == dict {
				valid = false
			}
			if !valid {
				fail()
				continue
			}
			if dict {
				d, ok := ex["dictionary"].(map[string]any)
				if !ok {
					fail()
					continue
				}
				for k, v := range d {
					if k != "wordList" {
						fail()
						continue
					}
					words, ok := v.([]any)
					if !ok || len(words) > 1000 {
						fail()
						continue
					}
					for _, word := range words {
						if s, ok := word.(string); !ok {
							fail()
						} else {
							totalBytes += len(s)
							if len(s) > 4000 || totalBytes > 1024*1024 {
								fail()
								out["rules"] = candidates
								return out
							}
						}
					}
				}
				continue
			}
			regex, ok := ex["regex"].(map[string]any)
			if !ok || len(regex) != 1 {
				fail()
				continue
			}
			pattern, ok := regex["pattern"].(string)
			if !ok || len(pattern) > 4000 {
				fail()
				continue
			}
			totalBytes += len(pattern)
			if totalBytes > 1024*1024 {
				fail()
				out["rules"] = candidates
				return out
			}
			if scope == "MATCHING_SCOPE_PARTIAL_MATCH" && (pattern == "(?s).*" || pattern == "(?s)^.*$") {
				candidates = append(candidates, Object{"rule_set_index": si, "rule_index": ri, "filter_types": cleanTypes, "matching_scope": scope, "catch_all": true})
			}
		}
	}
	out["rules"] = candidates
	return out
}
