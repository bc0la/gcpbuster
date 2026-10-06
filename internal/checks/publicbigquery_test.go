package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicBigQueryExactReadCapabilityScopes(t *testing.T) {
	for _, tc := range []struct{ typ, name, scope string }{
		{"bigquery.googleapis.com/Dataset", "//bigquery.googleapis.com/projects/demo/datasets/data", "dataset"},
		{"bigquery.googleapis.com/Table", "//bigquery.googleapis.com/projects/123/datasets/data/tables/table one", "table"},
		{"bigquery.googleapis.com/Table", "//bigquery.googleapis.com/projects/demo/datasets/data/tables/数据", "table"},
		{"cloudresourcemanager.googleapis.com/Project", "//cloudresourcemanager.googleapis.com/projects/123", "project"},
	} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": tc.name, "resourceType": tc.typ, "principal": "allAuthenticatedUsers", "permissions": []any{"bigquery.tables.getData"}})
		got := publicBigQueryCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Evidence["binding_scope"] != tc.scope {
			t.Fatal(tc, got)
		}
		a.Resource.Data["condition"] = inventory.Object{"expression": "true"}
		got = publicBigQueryCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Severity != "medium" {
			t.Fatal(got)
		}
		a.Resource.Data["permissions"] = []any{"bigquery.tables.get", "bigquery.tables.list", "bigquery.jobs.create"}
		if len(publicBigQueryCapabilities(a, time.Now())) != 0 {
			t.Fatal("metadata not data")
		}
	}
}

func TestPublicBigQueryRejectsUnsupportedPrincipalAndScope(t *testing.T) {
	base := func() inventory.Asset {
		return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//bigquery.googleapis.com/projects/demo/datasets/data", "resourceType": "bigquery.googleapis.com/Dataset", "principal": "allAuthenticatedUsers", "permissions": []any{"bigquery.tables.getData"}})
	}
	for _, p := range []string{"allUsers", "user:reader@example.com", "deleted:allAuthenticatedUsers", ""} {
		a := base()
		a.Resource.Data["principal"] = p
		if len(publicBigQueryCapabilities(a, time.Now())) != 0 {
			t.Fatal(p)
		}
	}
	for _, r := range []string{"//bigquery.googleapis.com/projects/demo/datasets/data/tables/table", "//bigquery.googleapis.com/projects/demo/datasets/../data", "https://bigquery.googleapis.com/projects/demo/datasets/data", "//bigquery.googleapis.com/projects/demo/datasets/data?x=y", "//bigquery.googleapis.com/projects/demo/datasets/data/routines/r"} {
		a := base()
		a.Resource.Data["resource"] = r
		if len(publicBigQueryCapabilities(a, time.Now())) != 0 {
			t.Fatal(r)
		}
	}
	a := base()
	a.Resource.Data["condition"] = true
	got := publicBigQueryCapabilities(a, time.Now())
	if len(got) != 1 || got[0].Evidence["condition_status"] != "malformed condition; applicability unknown" {
		t.Fatal(got)
	}
	a.Type = "bigquery.googleapis.com/Dataset"
	if len(publicBigQueryCapabilities(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}
