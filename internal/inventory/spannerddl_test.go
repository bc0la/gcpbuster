package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSpannerDDLAllTablesLexicalProjection(t *testing.T) {
	for _, sql := range []string{
		"CREATE CHANGE STREAM stream FOR ALL",
		"create /*note*/ change -- note\n stream `PRIVATE_NAME` for all;",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS (retention_period='7d', exclude_insert=TRUE)",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS (value_capture_type=\"NEW_VALUES\") ; # note",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS (retention_period='''7d''')",
		"CREATE CHANGE STREAM `a\\`b` FOR ALL OPTIONS (retention_period='a\\'b')",
	} {
		got, err := projectSpannerDDL(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if err != nil || len(got) != 1 {
			t.Fatalf("%q: %v %v", sql, got, err)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "retention") {
			t.Fatal(string(b))
		}
	}
}

func TestSpannerDDLNoSubstringOrUnsupportedClaims(t *testing.T) {
	for _, sql := range []string{
		"-- CREATE CHANGE STREAM s FOR ALL", "/* CREATE CHANGE STREAM s FOR ALL */",
		"CREATE TABLE t (v STRING(MAX) DEFAULT ('CREATE CHANGE STREAM s FOR ALL')) PRIMARY KEY(v)",
		"CREATE CHANGE STREAM s FOR selected_table", "CREATE CHANGE STREAM s FOR `ALL`",
		"CREATE CHANGE STREAM s FOR ALLISH", "SELECT '''CREATE CHANGE STREAM s FOR ALL'''",
	} {
		got, err := projectSpannerDDL(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		if err != nil || len(got) != 0 {
			t.Fatal(sql, got, err)
		}
	}
	for _, sql := range []string{
		"CREATE CHANGE STREAM s FOR ALL; SELECT 1", "CREATE CHANGE STREAM s FOR ALL_OPTIONS",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS ()", "CREATE CHANGE STREAM s FOR ALL OPTIONS (x=1)",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS (x='unterminated)", "CREATE CHANGE STREAM s FOR ALL /* bad",
		"CREATE CHANGE STREAM `` FOR ALL", "CREATE CHANGE STREAM s FOR ALL OPTIONS (x='x',)",
		"CREATE CHANGE STREAM FOR FOR ALL", "CREATE CHANGE STREAM SELECT FOR ALL",
		"CREATE CHANGE STREAM s FOR ALL OPTIONS (exclude_insert=TRUE,exclude_insert=FALSE)",
	} {
		got, err := projectSpannerDDL(Object{"statements": []any{sql}}, "GOOGLE_STANDARD_SQL")
		// ALL_OPTIONS is a selected-table identifier, not an all-table clause.
		if strings.HasSuffix(sql, "ALL_OPTIONS") {
			if len(got) != 0 {
				t.Fatal(got)
			}
			continue
		}
		if err == nil || len(got) != 0 {
			t.Fatal(sql, got, err)
		}
	}
}

func TestSpannerDDLBoundsAndPartialRetention(t *testing.T) {
	valid := "CREATE CHANGE STREAM s FOR ALL"
	got, err := projectSpannerDDL(Object{"statements": []any{false, valid, strings.Repeat("x", (4<<20)+1)}}, "GOOGLE_STANDARD_SQL")
	if err == nil || len(got) != 1 || Obj(got[0])["statement_index"] != 1 {
		t.Fatal(got, err)
	}
	for _, dialect := range []string{"", "POSTGRESQL", "DATABASE_DIALECT_UNSPECIFIED"} {
		if got, err := projectSpannerDDL(Object{"statements": []any{valid}}, dialect); err == nil || len(got) != 0 {
			t.Fatal(got, err)
		}
	}
	if _, err := projectSpannerDDL(Object{"statements": make([]any, 10001)}, "GOOGLE_STANDARD_SQL"); err == nil {
		t.Fatal("bound")
	}
	if _, err := projectSpannerDDL(Object{"statements": []any{strings.Repeat(";", 131073)}}, "GOOGLE_STANDARD_SQL"); err == nil {
		t.Fatal("token bound")
	}
}
