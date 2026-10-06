package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"time"
)

func loggingRoutes(a inventory.Asset, _ time.Time) []Result {
	if b(val(a, "disabled")) {
		return nil
	}
	destination := s(val(a, "destination"))
	if destination == "" {
		return nil
	}
	evidence := func() inventory.Object {
		return inventory.Object{"destination": destination, "writer_identity": val(a, "writerIdentity"), "include_children": val(a, "includeChildren"), "intercept_children": val(a, "interceptChildren"), "has_filter": s(val(a, "filter")) != "", "assessment": "Configured route only. Destination ownership, write authority, matching entries and successful delivery are unverified. Centralized exports can be intentional."}
	}
	var out []Result
	if strings.HasPrefix(destination, "storage.googleapis.com/") || strings.HasPrefix(destination, "pubsub.googleapis.com/") || strings.HasPrefix(destination, "bigquery.googleapis.com/") {
		out = append(out, Result{"medium", "Log sink exports to a storage, messaging or analytics destination", evidence(), "Verify destination ownership, readers and sink-writer permissions; reconcile the route with approved logging architecture and test delivery securely."})
	}
	if b(val(a, "interceptChildren")) {
		out = append(out, Result{"medium", "Aggregated log sink is configured to intercept descendant routing", evidence(), "Verify centralized retention and child-team visibility. Intercepted matching entries bypass child non-_Required sinks; _Required audit routing is not suppressed. Validate includeChildren and project-destination requirements against current API configuration."})
	} else if b(val(a, "includeChildren")) {
		out = append(out, Result{"info", "Aggregated log sink includes descendant resources", evidence(), "Review the aggregation scope, destination trust and filter against the intended organization/folder logging policy."})
	}
	return out
}
