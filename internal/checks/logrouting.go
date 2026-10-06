package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"math"
	"regexp"
	"strings"
	"time"
)

// Resource patterns include all four parent kinds even though custom bucket
// creation is project-only; see google/logging/v2/logging_config.proto LogBucket.
var loggingBucketName = regexp.MustCompile(`^(projects/[A-Za-z0-9][A-Za-z0-9._:-]*|folders/[0-9]+|organizations/[0-9]+|billingAccounts/[A-Za-z0-9][A-Za-z0-9-]*)/locations/[a-z][a-z0-9-]*/buckets/[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// loggingBucketRetention covers configuration review, not historical deletion.
// Cloud Logging (unlike Cloud Storage retention locking) documents that locked
// retention cannot be changed, including increased. No lock/update is performed.
// https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets
// https://docs.cloud.google.com/logging/docs/buckets#lock-bucket
func loggingBucketRetention(a inventory.Asset, _ time.Time) []Result {
	name := s(val(a, "name"))
	if !loggingBucketName.MatchString(name) || strings.HasSuffix(name, "/buckets/_Required") || s(val(a, "lifecycleState")) != "ACTIVE" {
		return nil
	}
	days, valid := loggingRetentionDays(val(a, "retentionDays"))
	if !valid {
		return nil // Omitted/zero are not interpreted as zero retention.
	}
	locked, lockKnown := val(a, "locked").(bool)
	if !lockKnown {
		return nil // Do not infer mutable/immutable from missing or malformed data.
	}
	if !locked && days != 1 {
		return nil
	}
	title := "Log bucket has a locked retention configuration"
	if days == 1 {
		title = "Log bucket explicitly retains entries for one day"
		if locked {
			title = "Log bucket has locked one-day retention"
		}
	}
	return result("info", title, "Review the intended retention requirement and other log copies. A locked Cloud Logging retention period cannot be changed; if requirements differ, plan an approved alternative route/bucket. Do not lock or delete resources as an assessment test.", inventory.Object{"retention_days": days, "locked": locked, "lifecycle_state": "ACTIVE", "assessment": "Explicit bucket configuration only. One day is the service minimum, not a universal compliance violation. Locking may be intentional protection. No retention-change history, attacker intent, deleted entries, actual delivery or absence of other copies is established; _Required routing is unaffected."})
}

func loggingRetentionDays(value any) (int, bool) {
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	default:
		return 0, false
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) || n < 1 || n > 3650 {
		return 0, false
	}
	return int(n), true
}
