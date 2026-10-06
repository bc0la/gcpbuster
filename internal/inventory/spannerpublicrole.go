package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

// projectSpannerPublicRole reads returned schema statements, never executes
// SQL. It recognizes table/column SELECT granted to public or named roles.
// Privilege lists, quoted grantees and schema-qualified tables are recognized;
// role inheritance is not inferred.
func projectSpannerPublicRole(raw Object, dialect string) (Object, error) {
	if dialect != "GOOGLE_STANDARD_SQL" {
		return nil, fmt.Errorf("unsupported FGAC schema dialect")
	}
	rows, ok := raw["statements"].([]any)
	if !ok || len(rows) > 10000 {
		return nil, fmt.Errorf("invalid FGAC schema statements")
	}
	count, named, columns, remaining := 0, 0, 0, 4<<20
	partial := false
	for _, r := range rows {
		sql, ok := r.(string)
		if !ok || len(sql) > remaining {
			return nil, fmt.Errorf("FGAC schema bound")
		}
		remaining -= len(sql)
		t, e := lexSpannerDDLCase(sql, true)
		if e != nil {
			// An unparsed statement could invalidate an earlier grant. Do not
			// retain positive privileges from a malformed schema response.
			return nil, fmt.Errorf("malformed FGAC schema statement")
		}
		word := func(i int, v string) bool { return i < len(t) && t[i].kind == 'w' && strings.EqualFold(t[i].value, v) }
		identifier := func(i int) bool {
			if i >= len(t) {
				return false
			}
			token := t[i]
			token.value = strings.ToUpper(token.value)
			return spannerDDLIdentifier(token)
		}
		if word(0, "REVOKE") {
			return nil, fmt.Errorf("noncanonical revoke schema unsupported")
		}
		if !word(0, "GRANT") {
			continue
		}
		pos, columnScope, selected, valid := 1, false, false, true
		seen := map[string]bool{}
		for {
			if pos >= len(t) || t[pos].kind != 'w' {
				valid = false
				break
			}
			priv := strings.ToUpper(t[pos].value)
			if (priv != "SELECT" && priv != "INSERT" && priv != "UPDATE" && priv != "DELETE") || seen[priv] {
				valid = false
				break
			}
			seen[priv] = true
			pos++
			hasColumns := false
			if pos < len(t) && t[pos].value == "(" {
				hasColumns = true
				if priv == "DELETE" {
					valid = false
					break
				}
				pos++
				for {
					if !identifier(pos) {
						valid = false
						break
					}
					pos++
					if pos < len(t) && t[pos].value == "," {
						pos++
						continue
					}
					break
				}
				if !valid || pos >= len(t) || t[pos].value != ")" {
					valid = false
					break
				}
				pos++
			}
			if priv == "SELECT" {
				selected = true
				columnScope = hasColumns
			}
			if pos < len(t) && t[pos].value == "," {
				pos++
				continue
			}
			break
		}
		if !valid || !word(pos, "ON") || !word(pos+1, "TABLE") {
			partial = true
			continue
		}
		pos += 2
		for {
			if !identifier(pos) {
				valid = false
				break
			}
			pos++
			if pos < len(t) && t[pos].value == "." {
				pos++
				if !identifier(pos) {
					valid = false
					break
				}
				pos++
			}
			if pos < len(t) && t[pos].value == "," {
				pos++
				continue
			}
			break
		}
		if !valid || !word(pos, "TO") || !word(pos+1, "ROLE") {
			partial = true
			continue
		}
		pos += 2
		publicGrant, namedGrant := false, false
		for {
			if !identifier(pos) {
				valid = false
				break
			}
			role := t[pos].value
			// Role identifiers have ordinary identifier spelling, including when
			// quoted. Escaped or compound quoted forms are not guessed.
			if !spannerGrantRoleName.MatchString(role) {
				valid = false
				break
			}
			if role == "public" {
				publicGrant = true
			} else {
				namedGrant = true
			}
			pos++
			if pos < len(t) && t[pos].value == "," {
				pos++
				continue
			}
			break
		}
		if pos < len(t) && t[pos].value == ";" {
			pos++
		}
		if !valid || pos != len(t) {
			partial = true
			continue
		}
		if !selected {
			continue
		}
		if publicGrant {
			count++
		}
		if namedGrant {
			named++
		}
		if columnScope {
			columns++
		}
	}
	out := Object{"dialect": "GOOGLE_STANDARD_SQL", "public_table_select_grants": count, "named_role_select_grants": named, "column_scoped_select_grants": columns, "syntax_coverage": "selected_supported_statements_only"}
	if partial {
		return out, fmt.Errorf("some FGAC grant syntax unassessed")
	}
	return out, nil
}

var spannerPublicDatabase = regexp.MustCompile(`^//spanner\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9_-]*/instances/[a-z][a-z0-9-]*/databases/[A-Za-z][A-Za-z0-9_-]*$`)

var spannerGrantRoleName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,117}$`)

func CorrelateSpannerPublicRole(out *Snapshot) {
	for i := range out.Assets {
		if out.Assets[i].Type == PermissionGrantType {
			delete(out.Assets[i].Resource.Data, "_gcpbusterSpannerPublicRole")
		}
	}
	if len(out.Assets) > 100000 {
		out.Coverage = append(out.Coverage, Coverage{Source: "spanner-public-role", Status: "incomplete", Error: "Snapshot correlation bound"})
		return
	}
	type countSet struct{ public, named int }
	counts := map[string]countSet{}
	conflicts := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "spanner.googleapis.com/Database" || !spannerPublicDatabase.MatchString(a.Name) {
			continue
		}
		d := Obj(a.Resource.Data["_gcpbusterSpannerPublicRoleDDL"])
		n, ok := d["public_table_select_grants"].(int)
		if f, yes := d["public_table_select_grants"].(float64); yes && float64(int(f)) == f {
			n = int(f)
			ok = true
		}
		if !ok || n < 0 || n > 10000 || d["dialect"] != "GOOGLE_STANDARD_SQL" || d["syntax_coverage"] != "selected_supported_statements_only" {
			conflicts[a.Name] = true
			continue
		}
		named := 0
		if raw, exists := d["named_role_select_grants"]; exists {
			switch v := raw.(type) {
			case int:
				named = v
			case float64:
				if float64(int(v)) != v {
					conflicts[a.Name] = true
					continue
				}
				named = int(v)
			default:
				conflicts[a.Name] = true
				continue
			}
			if named < 0 || named > 10000 {
				conflicts[a.Name] = true
				continue
			}
		}
		set := countSet{n, named}
		if old, ok := counts[a.Name]; ok && old != set {
			conflicts[a.Name] = true
		}
		counts[a.Name] = set
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		d := a.Resource.Data
		resource := Str(d["resource"])
		set := counts[resource]
		if a.Type != PermissionGrantType || d["resourceType"] != "spanner.googleapis.com/Database" || !spannerPublicDatabase.MatchString(resource) || conflicts[resource] || set.public+set.named == 0 {
			continue
		}
		d["_gcpbusterSpannerPublicRole"] = Object{"database": resource, "public_table_select_grants": set.public, "named_role_select_grants": set.named, "scope": "exact_database_schema_observation"}
	}
}
