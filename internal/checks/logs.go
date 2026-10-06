package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func logContentSecrets(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "matches")) {
		m := obj(v)
		if s(m["rule"]) == "" {
			continue
		}
		out = append(out, Result{"high", "Potential credential in Cloud Logging entry", inventory.Object{"rule": m["rule"], "log_name": m["logName"], "timestamp": m["timestamp"], "insert_id": m["insertId"], "payload_field": m["payloadField"], "line": m["line"], "value": "[REDACTED]", "window_complete": val(a, "complete"), "assessment": "pattern match in visible retained logs; credential validity not tested"}, "Inspect the entry securely, rotate any exposed credential, restrict log access and remove credential output from the producer."})
	}
	return out
}
