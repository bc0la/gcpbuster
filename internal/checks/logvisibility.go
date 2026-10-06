package checks

import (
	"sort"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

// loggingBucketVisibility reports explicit lifecycle/field configuration, not
// successful blinding, historical deletion or effective reader authorization.
func loggingBucketVisibility(a inventory.Asset, _ time.Time) []Result {
	name := s(val(a, "name"))
	if !loggingBucketName.MatchString(name) {
		return nil
	}
	state := s(val(a, "lifecycleState"))
	if state == "DELETE_REQUESTED" {
		if strings.HasSuffix(name, "/buckets/_Required") || strings.HasSuffix(name, "/buckets/_Default") {
			return nil
		}
		return result("medium", "Log bucket is pending deletion", "Confirm that deleting this bucket is authorized and that required evidence has another approved retention path. If deletion is unintended, have an authorized administrator review recovery promptly; this tool does not undelete or modify it.", inventory.Object{"lifecycle_state": state, "assessment": "The API explicitly reports pending deletion. Logging documents a seven-day recovery period after the deletion request and continues routing during that period. The deletion-request time, remaining recovery window, actor, intent, contents and other copies are unknown; no deadline is inferred from updateTime."})
	}
	if state != "ACTIVE" {
		return nil
	}
	fields, ok := val(a, "restrictedFields").([]any)
	if !ok || len(fields) == 0 {
		return nil
	}
	allowed := map[string]bool{"textPayload": true, "jsonPayload": true, "protoPayload": true, "httpRequest": true, "labels": true, "sourceLocation": true}
	seen := map[string]bool{}
	for _, raw := range fields {
		field, ok := raw.(string)
		root := strings.SplitN(field, ".", 2)[0]
		if !ok || strings.TrimSpace(field) != field || !allowed[root] || strings.HasSuffix(field, ".") {
			return nil
		}
		seen[field] = true
	}
	names := make([]string, 0, len(seen))
	for field := range seen {
		names = append(names, field)
	}
	sort.Strings(names)
	return result("info", "Log bucket configures field-level read restrictions", "Review that field restrictions protect sensitive values without unexpectedly hiding fields needed by investigators. Review Field Accessor and linked BigQuery authorization separately; do not remove protective restrictions as a test.", inventory.Object{"restricted_fields": names, "assessment": "Explicit configuration only; restrictions can be intentional protection. They affect Logging readers lacking logging.fields.access, not every reader. Linked BigQuery datasets use a separate authorization surface and do not honor these restrictions, but no linked dataset, bypass, actual hidden data or effective reader access is established."})
}
