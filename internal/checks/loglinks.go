package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var loggingLinkID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var loggingLinkDataset = regexp.MustCompile(`^bigquery\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/datasets/([A-Za-z0-9_]+)$`)

func loggingBigQueryLink(a inventory.Asset, _ time.Time) []Result {
	name := s(val(a, "name"))
	parts := strings.Split(name, "/")
	if len(parts) != 8 || !loggingBucketName.MatchString(strings.Join(parts[:6], "/")) || parts[6] != "links" || !loggingLinkID.MatchString(parts[7]) || s(val(a, "lifecycleState")) != "ACTIVE" {
		return nil
	}
	dataset := s(val(a, "bigqueryDataset", "datasetId"))
	match := loggingLinkDataset.FindStringSubmatch(dataset)
	if match == nil || match[1] != parts[7] {
		return nil
	}
	return result("info", "Log bucket has an active BigQuery linked dataset", "Review linked-dataset and BigQuery view authorization separately from Logging authorization. Confirm this additional query surface is intended; do not query logs or change access as a test.", inventory.Object{"dataset": dataset, "lifecycle_state": "ACTIVE", "assessment": "Explicit active link configuration only. This does not establish public exposure, effective reader access, log contents or successful queries. Logging field restrictions do not establish equivalent restrictions on the linked BigQuery surface."})
}
