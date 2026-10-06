package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSpannerPublicRoleDDLSubsetRedacted(t *testing.T) {
	raw := Object{"statements": []any{"GRANT SELECT ON TABLE SensitiveTable TO ROLE public;", "GRANT SELECT ON TABLE `OTHER_SECRET`, AnotherTable TO ROLE public", "CREATE TABLE unrelated (id INT64) PRIMARY KEY(id)"}}
	got, e := projectSpannerPublicRole(raw, "GOOGLE_STANDARD_SQL")
	if e != nil || got["public_table_select_grants"] != 2 {
		t.Fatal(got, e)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "Sensitive") || strings.Contains(string(b), "SECRET") {
		t.Fatal(string(b))
	}
	for _, sql := range []string{"GRANT SELECT ON TABLE T TO ROLE other", "GRANT SELECT ON TABLE T TO ROLE 'public'", "SELECT 'GRANT SELECT ON TABLE T TO ROLE public'", "-- GRANT SELECT ON TABLE T TO ROLE public", "GRANT SELECT ON TABLE T TO ROLE public; SELECT 1", "GRANT SELECT ON TABLE T TO ROLE public,"} {
		got, _ := projectSpannerPublicRole(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if got["public_table_select_grants"] != 0 {
			t.Fatal(sql, got)
		}
	}
	if got, _ := projectSpannerPublicRole(Object{"statements": []any{"GRANT SELECT ON TABLE T TO ROLE public", "REVOKE SELECT ON TABLE T FROM ROLE public"}}, "GOOGLE_STANDARD_SQL"); got != nil {
		t.Fatal("historical revoke", got)
	}
	if got, _ := projectSpannerPublicRole(raw, "POSTGRESQL"); got != nil {
		t.Fatal("dialect")
	}
}

func TestSpannerPublicRoleCanonicalGrantVariants(t *testing.T) {
	for _, sql := range []string{
		"GRANT SELECT ON TABLE T TO ROLE `public`",
		"GRANT INSERT, SELECT, UPDATE(location) ON TABLE schema_name.T TO ROLE public",
		"GRANT UPDATE(location), SELECT(name) ON TABLE `schema_name`.`T`, other TO ROLE analyst, `public`",
		"GRANT DELETE, SELECT ON TABLE T TO ROLE public, analyst",
	} {
		got, err := projectSpannerPublicRole(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if err != nil || got["public_table_select_grants"] != 1 {
			t.Fatal(sql, got, err)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "schema_name") || strings.Contains(string(encoded), "analyst") {
			t.Fatal(string(encoded))
		}
	}
	for _, sql := range []string{
		"GRANT INSERT, UPDATE(location) ON TABLE schema_name.T TO ROLE public",
		"GRANT SELECT ON TABLE T TO ROLE `Public`",
		"GRANT SELECT ON TABLE T TO ROLE `pub\\x6cic`",
		"GRANT SELECT, DELETE(c) ON TABLE T TO ROLE public",
		"GRANT SELECT ON TABLE a.b.c TO ROLE public",
		"GRANT SELECT, SELECT(c) ON TABLE T TO ROLE public",
	} {
		got, _ := projectSpannerPublicRole(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if got["public_table_select_grants"] != 0 {
			t.Fatal(sql, got)
		}
	}
}

func TestSpannerPublicRoleExactDatabaseConflictAndNoInheritance(t *testing.T) {
	const db = "//spanner.googleapis.com/projects/demo/instances/instance/databases/data"
	marker := Object{"dialect": "GOOGLE_STANDARD_SQL", "public_table_select_grants": 1, "syntax_coverage": "selected_supported_statements_only"}
	asset := NewAsset(db, "spanner.googleapis.com/Database", Object{"_gcpbusterSpannerPublicRoleDDL": marker})
	grant := NewAsset("grant", PermissionGrantType, Object{"resource": db, "resourceType": "spanner.googleapis.com/Database"})
	s := Snapshot{Assets: []Asset{asset, grant}}
	CorrelateSpannerPublicRole(&s)
	if Get(s.Assets[1].Resource.Data, "_gcpbusterSpannerPublicRole", "public_table_select_grants") != 1 {
		t.Fatal(s)
	}
	s.Assets = append(s.Assets, NewAsset(db, "spanner.googleapis.com/Database", Object{}), asset)
	CorrelateSpannerPublicRole(&s)
	if s.Assets[1].Resource.Data["_gcpbusterSpannerPublicRole"] != nil {
		t.Fatal("ambiguous metadata restored")
	}
	s = Snapshot{Assets: []Asset{asset, NewAsset("project", PermissionGrantType, Object{"resource": "//cloudresourcemanager.googleapis.com/projects/demo", "resourceType": "cloudresourcemanager.googleapis.com/Project"})}}
	CorrelateSpannerPublicRole(&s)
	if s.Assets[1].Resource.Data["_gcpbusterSpannerPublicRole"] != nil {
		t.Fatal("project expansion")
	}
}

func TestSpannerPublicRoleColumnsNamedAndCasePreservation(t *testing.T) {
	raw := Object{"statements": []any{"GRANT SELECT(secret_column,`other`) ON TABLE T TO ROLE public", "grant select ON TABLE T TO ROLE Public", "GRANT SELECT ON TABLE T TO ROLE analyst"}}
	got, e := projectSpannerPublicRole(raw, "GOOGLE_STANDARD_SQL")
	if e != nil || got["public_table_select_grants"] != 1 || got["named_role_select_grants"] != 2 || got["column_scoped_select_grants"] != 1 {
		t.Fatal(got, e)
	}
	for _, sql := range []string{"GRANT SELECT() ON TABLE T TO ROLE public", "GRANT SELECT(c,) ON TABLE T TO ROLE public", "GRANT SELECT(c) UPDATE(d) ON TABLE T TO ROLE public"} {
		got, _ := projectSpannerPublicRole(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if got["public_table_select_grants"] != 0 {
			t.Fatal(sql, got)
		}
	}
}

func TestSpannerPublicRoleMalformedSchemaSuppressesPriorGrants(t *testing.T) {
	for _, sql := range []string{"REVOKE SELECT ON TABLE T FROM ROLE public /*", "REVOKE SELECT ON TABLE `unterminated", "REVOKE " + strings.Repeat("x ", 70000)} {
		got, err := projectSpannerPublicRole(Object{"statements": []any{"GRANT SELECT ON TABLE T TO ROLE public", sql}}, "GOOGLE_STANDARD_SQL")
		if err == nil || got != nil {
			t.Fatal("malformed later statement retained grant", got, err)
		}
	}
}
