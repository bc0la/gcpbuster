package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

// Explicit disabled state only; omitted configuration and metric/alert absence
// are unknown, not a conclusion about logging delivery or tampering.
func loggingMetrics(a inventory.Asset, _ time.Time) []Result {
	disabled, known := val(a, "disabled").(bool)
	if !known || !disabled {
		return nil
	}
	return result("low", "Logs-based metric is disabled", "Confirm that disabling this metric is intentional and review any dependent monitoring separately. This tool does not enable metrics or modify alert policies.", inventory.Object{"disabled": true, "assessment": "The metric explicitly reports disabled and therefore does not generate new points. Existing time series, dependent alerts, log collection, actor, intent and historical changes are not established."})
}
