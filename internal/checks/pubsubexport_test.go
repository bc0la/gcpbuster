package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestPubSubExportExplicitIdentityDestinations(t *testing.T) {
	for _, tc := range []struct{ key, field, destination, service string }{
		{"bigqueryConfig", "table", "target-project.dataset.messages", "BigQuery"},
		{"cloudStorageConfig", "bucket", "export-bucket", "Cloud Storage"},
		{"bigtableConfig", "table", "projects/target-project/instances/messages/tables/archive", "Bigtable"},
	} {
		a := inventory.NewAsset("subscription", "pubsub.googleapis.com/Subscription", inventory.Object{tc.key: inventory.Object{tc.field: tc.destination, "serviceAccountEmail": "writer@source-project.iam.gserviceaccount.com", "state": "PERMISSION_DENIED", "filenamePrefix": "secret-sentinel", "unexpected": "secret-sentinel"}})
		got := pubsubExportIdentity(a, time.Now())
		if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["destination"] != tc.destination || !strings.Contains(got[0].Title, tc.service) {
			t.Fatal(tc, got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), "secret-sentinel") || !strings.Contains(string(raw), "unverified") {
			t.Fatal(string(raw))
		}
	}
}

func TestPubSubExportMissingMalformedAndDefaultUnknown(t *testing.T) {
	conflict := inventory.NewAsset("subscription", "pubsub.googleapis.com/Subscription", inventory.Object{
		"pushConfig":         inventory.Object{"pushEndpoint": "https://example.test"},
		"cloudStorageConfig": inventory.Object{"bucket": "export-bucket", "serviceAccountEmail": "writer@source-project.iam.gserviceaccount.com"},
	})
	if got := pubsubExportIdentity(conflict, time.Time{}); len(got) != 0 {
		t.Fatal("conflicting delivery evidence", got)
	}
	for _, cfg := range []any{nil, "bad", []any{}, inventory.Object{}, inventory.Object{"bucket": "export-bucket"}, inventory.Object{"bucket": "export-bucket", "serviceAccountEmail": false}, inventory.Object{"bucket": "https://user:password@example.com", "serviceAccountEmail": "writer@source-project.iam.gserviceaccount.com"}, inventory.Object{"bucket": "export-bucket", "serviceAccountEmail": "writer@evil.example"}} {
		a := inventory.NewAsset("subscription", "pubsub.googleapis.com/Subscription", inventory.Object{"cloudStorageConfig": cfg})
		if got := pubsubExportIdentity(a, time.Now()); len(got) != 0 {
			t.Fatal(cfg, got)
		}
	}
	for _, dest := range []string{"gs://export-bucket", "1.2.3.4", "two..dots", "a/b", "a\nb", "ab", strings.Repeat("a", 64)} {
		if pubsubExportBucket(dest) {
			t.Fatal(dest)
		}
	}
	for _, dest := range []string{"https://user:pass@example.com", "project.dataset.table?token=secret", "project.dataset.table/path", "project.dataset.table\n"} {
		if pubsubExportBQ.MatchString(dest) {
			t.Fatal(dest)
		}
	}
	a := inventory.NewAsset("topic", "pubsub.googleapis.com/Topic", inventory.Object{"cloudStorageConfig": inventory.Object{"bucket": "export-bucket", "serviceAccountEmail": "writer@source-project.iam.gserviceaccount.com"}})
	if got := pubsubExportIdentity(a, time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}
