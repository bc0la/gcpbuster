package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestSpannerDatabaseProtectionExplicitOnly(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{}`, 0}, {`{"enableDropProtection":true}`, 0}, {`{"enableDropProtection":"false"}`, 0},
		{`{"enableDropProtection":null}`, 0}, {`{"enableDropProtection":0}`, 0},
		{`{"enableDropProtection":false,"versionRetentionPeriod":"1h","state":"SENTINEL"}`, 1},
		{`{"versionRetentionPeriod":"1h"}`, 0},
	} {
		got := spannerDatabaseProtection(asset("spanner.googleapis.com/Database", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 {
			raw, _ := json.Marshal(got)
			if got[0].Severity != "low" || strings.Contains(string(raw), "SENTINEL") || !strings.Contains(string(raw), "does not prevent row mutation") {
				t.Fatal(string(raw))
			}
		}
	}
	for _, typ := range []string{"spanner.googleapis.com/Instance", "spanner.googleapis.com/Backup", "sqladmin.googleapis.com/Database"} {
		if got := spannerDatabaseProtection(asset(typ, `{"enableDropProtection":false}`), time.Now()); len(got) != 0 {
			t.Fatal(typ, got)
		}
	}
}

func TestSpannerChangeStreamScopeValidatedCandidates(t *testing.T) {
	base := func() inventory.Object {
		return inventory.Object{"statement_index": 0, "tracking_scope": "all_tables", "dialect": "GOOGLE_STANDARD_SQL"}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"statement_index", -1}, {"statement_index", 10000}, {"statement_index", 0.5}, {"statement_index", "0"},
		{"tracking_scope", "selected_tables"}, {"tracking_scope", nil}, {"dialect", "POSTGRESQL"}, {"dialect", nil},
	} {
		d := base()
		d[tc.key] = tc.value
		a := inventory.NewAsset("db", "spanner.googleapis.com/Database", inventory.Object{"_gcpbusterChangeStreams": []any{d}})
		if got := spannerChangeStreamScope(a, time.Now()); len(got) != 0 {
			t.Fatal(tc, got)
		}
	}
	d := base()
	d["sql"] = "PRIVATE_SOURCE"
	d["name"] = "PRIVATE_NAME"
	a := inventory.NewAsset("db", "spanner.googleapis.com/Database", inventory.Object{"_gcpbusterChangeStreams": []any{d, d}})
	got := spannerChangeStreamScope(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE") || !strings.Contains(string(b), "Capture options can exclude") {
		t.Fatal(string(b))
	}
	a.Type = "spanner.googleapis.com/Instance"
	if len(spannerChangeStreamScope(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}
