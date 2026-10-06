package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net"
	"regexp"
	"strings"
	"time"
)

// Conservative identifier subsets, not a complete product name validator.
// Reject URLs, credentials and arbitrary embedded text from report evidence.
var pubsubExportSA = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
var pubsubExportBQ = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]\.[A-Za-z0-9_]+\.[A-Za-z0-9_-]+$`)
var pubsubExportBT = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+)/instances/[a-z][a-z0-9-]{4,31}[a-z0-9]/tables/[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$`)
var pubsubExportBucketPart = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*[a-z0-9]$|^[a-z0-9]$`)

func pubsubExportBucket(name string) bool {
	if len(name) < 3 || len(name) > 222 || net.ParseIP(name) != nil {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) > 63 || !pubsubExportBucketPart.MatchString(part) {
			return false
		}
	}
	return true
}

// REST configuration establishes an explicitly selected writer, not successful
// delivery, destination permissions, creator intent or an impersonation path.
// https://docs.cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions
func pubsubExportIdentity(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "pubsub.googleapis.com/Subscription" {
		return nil
	}
	// The API defines a delivery union. Conflicting supplied branches are
	// malformed evidence, not several simultaneously configured destinations.
	branches := 0
	for _, key := range []string{"pushConfig", "bigqueryConfig", "cloudStorageConfig", "bigtableConfig"} {
		if len(obj(val(a, key))) > 0 {
			branches++
		}
	}
	if branches != 1 {
		return nil
	}
	var out []Result
	for _, spec := range []struct {
		config, field, service string
		valid                  func(string) bool
	}{
		{"bigqueryConfig", "table", "BigQuery", pubsubExportBQ.MatchString},
		{"cloudStorageConfig", "bucket", "Cloud Storage", pubsubExportBucket},
		{"bigtableConfig", "table", "Bigtable", pubsubExportBT.MatchString},
	} {
		cfg := obj(val(a, spec.config))
		email, destination := s(cfg["serviceAccountEmail"]), s(cfg[spec.field])
		if !pubsubExportSA.MatchString(email) || len(destination) > 2080 || !spec.valid(destination) {
			continue
		}
		out = append(out, Result{"info", "Pub/Sub export explicitly selects a service account for " + spec.service,
			inventory.Object{"service_account": email, "destination_service": spec.service, "destination": destination,
				"assessment": "Explicit configured export identity and destination only; destination access, delivery, creator actAs, service-agent token permissions and attacker control are unverified. This is not token disclosure, general impersonation or code execution. No default service agent is inferred."},
			"Review the selected writer, destination ownership and who may change the subscription. Validate effective destination permissions and business approval without publishing, consuming or replaying messages."})
	}
	return out
}
