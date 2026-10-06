package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"math"
	"regexp"
	"time"
)

var serviceHistoryID = regexp.MustCompile(`^[a-z0-9._-]{1,63}$`)

func serviceConfigHistoryEvidence(a inventory.Asset) []any {
	out := []any{}
	statuses := map[string]bool{"ROLLOUT_STATUS_UNSPECIFIED": true, "IN_PROGRESS": true, "SUCCESS": true, "CANCELLED": true, "FAILED": true, "PENDING": true, "FAILED_ROLLED_BACK": true}
	for _, entry := range arr(val(a, "_gcpbusterRolloutHistory")) {
		r := obj(entry)
		id, status, stamp := s(r["rolloutId"]), s(r["status"]), s(r["createTime"])
		weight, ok := r["percentage"].(float64)
		if !serviceHistoryID.MatchString(id) || id == "." || id == ".." || !statuses[status] || !ok || math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 || weight > 100 {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
			continue
		}
		out = append(out, inventory.Object{"rollout_id": id, "status": status, "created_at": stamp, "percentage": weight, "temporal_scope": "retained_history_not_current"})
	}
	return out
}
