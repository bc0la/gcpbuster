package inventory

import (
	"fmt"
	"strings"
)

type spannerDDLToken struct {
	kind  byte
	value string
}

// projectSpannerDDL recognizes only a narrow returned GoogleSQL CREATE CHANGE
// STREAM form. It never executes SQL or retains identifiers or option values.
func projectSpannerDDL(raw Object, dialect string) ([]any, error) {
	if dialect != "GOOGLE_STANDARD_SQL" {
		return nil, fmt.Errorf("unsupported Spanner DDL dialect")
	}
	rows, ok := raw["statements"].([]any)
	if !ok || len(rows) > 10000 {
		return nil, fmt.Errorf("invalid Spanner DDL statements")
	}
	out := []any{}
	remaining := 4 << 20
	partial := false
	for index, raw := range rows {
		sql, ok := raw.(string)
		if !ok || len(sql) > remaining {
			partial = true
			continue
		}
		remaining -= len(sql)
		t, err := lexSpannerDDL(sql)
		if err != nil {
			partial = true
			continue
		}
		word := func(i int, value string) bool { return i < len(t) && t[i].kind == 'w' && t[i].value == value }
		if !word(0, "CREATE") || !word(1, "CHANGE") || !word(2, "STREAM") {
			continue
		}
		if len(t) < 6 || !spannerDDLIdentifier(t[3]) || !word(4, "FOR") {
			partial = true
			continue
		}
		if !word(5, "ALL") {
			continue
		} // Selected-table streams are outside this indicator.
		pos := 6
		if word(pos, "OPTIONS") {
			pos++
			if pos >= len(t) || t[pos].value != "(" {
				partial = true
				continue
			}
			pos++
			valid, count := true, 0
			seenOptions := map[string]bool{}
			for pos < len(t) && t[pos].value != ")" {
				if count > 0 {
					if t[pos].value != "," {
						valid = false
						break
					}
					pos++
				}
				if pos+2 >= len(t) || t[pos].kind != 'w' || t[pos+1].value != "=" {
					valid = false
					break
				}
				v := t[pos+2]
				key := t[pos].value
				stringOption := key == "RETENTION_PERIOD" || key == "VALUE_CAPTURE_TYPE"
				boolOption := key == "EXCLUDE_TTL_DELETES" || key == "EXCLUDE_INSERT" || key == "EXCLUDE_UPDATE" || key == "EXCLUDE_DELETE" || key == "ALLOW_TXN_EXCLUSION"
				if seenOptions[key] || !(stringOption && v.kind == 's' || boolOption && v.kind == 'w' && (v.value == "TRUE" || v.value == "FALSE")) {
					valid = false
					break
				}
				seenOptions[key] = true
				pos += 3
				count++
			}
			if !valid || count == 0 || pos >= len(t) || t[pos].value != ")" {
				partial = true
				continue
			}
			pos++
		}
		if pos < len(t) && t[pos].value == ";" {
			pos++
		}
		if pos != len(t) {
			partial = true
			continue
		}
		out = append(out, Object{"statement_index": index, "tracking_scope": "all_tables", "dialect": "GOOGLE_STANDARD_SQL"})
	}
	if partial {
		return out, fmt.Errorf("some Spanner DDL statements were malformed, oversized or unsupported")
	}
	return out, nil
}

func lexSpannerDDL(sql string) ([]spannerDDLToken, error) {
	return lexSpannerDDLCase(sql, false)
}

func lexSpannerDDLCase(sql string, preserveCase bool) ([]spannerDDLToken, error) {
	out := []spannerDDLToken{}
	for i := 0; i < len(sql); {
		if len(out) >= 131072 {
			return nil, fmt.Errorf("Spanner DDL token limit exceeded")
		}
		c := sql[i]
		if strings.ContainsRune(" \t\r\n\f", rune(c)) {
			i++
			continue
		}
		if c == '#' || (c == '-' && i+1 < len(sql) && sql[i+1] == '-') {
			for i < len(sql) && sql[i] != '\n' && sql[i] != '\r' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(sql) && sql[i+1] == '*' {
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated DDL comment")
			}
			i += end + 4
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			kind := byte('s')
			if c == '`' {
				kind = 'i'
			}
			width := 1
			if c != '`' && i+2 < len(sql) && sql[i+1] == c && sql[i+2] == c {
				width = 3
			}
			i += width
			start := i
			closed := false
			for i < len(sql) {
				if sql[i] == '\\' {
					if i+1 >= len(sql) {
						break
					}
					i += 2
					continue
				}
				if sql[i] == c && (width == 1 || (i+2 < len(sql) && sql[i+1] == c && sql[i+2] == c)) {
					if kind == 'i' && i == start {
						return nil, fmt.Errorf("empty DDL identifier")
					}
					i += width
					closed = true
					break
				}
				if width == 1 && (sql[i] == '\n' || sql[i] == '\r') {
					return nil, fmt.Errorf("newline in quoted DDL token")
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted DDL token")
			}
			value := ""
			if preserveCase && kind == 'i' {
				value = sql[start : i-width]
			}
			out = append(out, spannerDDLToken{kind, value})
			continue
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			start := i
			i++
			for i < len(sql) {
				b := sql[i]
				if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_') {
					break
				}
				i++
			}
			value := sql[start:i]
			if !preserveCase {
				value = strings.ToUpper(value)
			}
			out = append(out, spannerDDLToken{'w', value})
			continue
		}
		out = append(out, spannerDDLToken{'p', string(c)})
		i++
	}
	return out, nil
}

func spannerDDLIdentifier(t spannerDDLToken) bool {
	if t.kind == 'i' {
		return true
	}
	if t.kind != 'w' || len(t.value) == 0 || len(t.value) > 118 || t.value[0] == '_' {
		return false
	}
	// GoogleSQL reserved keywords cannot be unquoted identifiers.
	reserved := " ALL AND ANY ARRAY AS ASC ASSERT_ROWS_MODIFIED AT BETWEEN BY CASE CAST COLLATE CONTAINS CREATE CROSS CUBE CURRENT DEFAULT DEFINE DESC DISTINCT ELSE END ENUM ESCAPE EXCEPT EXCLUDE EXISTS EXTRACT FALSE FETCH FOLLOWING FOR FROM FULL GROUP GROUPING GROUPS HASH HAVING IF IGNORE IN INNER INTERSECT INTERVAL INTO IS JOIN LATERAL LEFT LIKE LIMIT LOOKUP MERGE NATURAL NEW NO NOT NULL NULLS OF ON OR ORDER OUTER OVER PARTITION PRECEDING PROTO QUALIFY RANGE RECURSIVE RESPECT RIGHT ROLLUP ROWS SELECT SET SOME STRUCT TABLESAMPLE THEN TO TREAT TRUE UNBOUNDED UNION UNNEST USING WHEN WHERE WINDOW WITH WITHIN "
	return !strings.Contains(reserved, " "+t.value+" ")
}
