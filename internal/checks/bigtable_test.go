package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestBigtableTableProtectionExplicitOnly(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{{`{}`, 0}, {`{"deletionProtection":true}`, 0}, {`{"deletionProtection":"false"}`, 0}, {`{"deletionProtection":null}`, 0}, {`{"deletionProtection":false}`, 1}} {
		got := bigtableTableProtection(asset("bigtableadmin.googleapis.com/Table", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
	if got := bigtableTableProtection(asset("bigtableadmin.googleapis.com/AuthorizedView", `{"deletionProtection":false}`), time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestBigtableAuthorizedViewScopeValidatedSubsetOnly(t *testing.T) {
	base := func() inventory.Object {
		return inventory.Object{"complete": true, "all_rows": true, "row_prefix_count": 1, "family_count": 3, "all_qualifiers_family_count": 2}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"complete", false}, {"complete", "true"}, {"all_rows", false}, {"all_rows", "true"},
		{"row_prefix_count", nil}, {"row_prefix_count", 0}, {"row_prefix_count", 10001},
		{"family_count", 0}, {"family_count", "3"}, {"family_count", 1},
		{"all_qualifiers_family_count", 0}, {"all_qualifiers_family_count", -1}, {"all_qualifiers_family_count", 1.5},
	} {
		d := base()
		d[tc.key] = tc.value
		a := inventory.NewAsset("view", inventory.BigtableAuthorizedViewType, inventory.Object{"subset_scope": d})
		if got := bigtableAuthorizedViewScope(a, time.Now()); len(got) != 0 {
			t.Fatalf("%s=%v: %v", tc.key, tc.value, got)
		}
	}
	a := inventory.NewAsset("view", inventory.BigtableAuthorizedViewType, inventory.Object{"subset_scope": base(), "family_name": "sentinel-family", "prefix": "sentinel-prefix"})
	got := bigtableAuthorizedViewScope(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["all_qualifiers_family_count"] != 2 {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "sentinel") || !strings.Contains(string(raw), "does not include every table family") {
		t.Fatal(string(raw))
	}
	// Ordinary table metadata and unprojected selector fields are not evidence.
	a.Type = "bigtableadmin.googleapis.com/Table"
	if len(bigtableAuthorizedViewScope(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
	a = inventory.NewAsset("view", inventory.BigtableAuthorizedViewType, inventory.Object{"subsetView": inventory.Object{"rowPrefixes": []any{""}}})
	if len(bigtableAuthorizedViewScope(a, time.Now())) != 0 {
		t.Fatal("unvalidated source")
	}
}
