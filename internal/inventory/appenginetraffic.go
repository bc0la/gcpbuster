package inventory

import "math"

// TrafficSplit allocations must be positive fractions summing to one. Missing
// or malformed splits are unknown, never evidence of an unallocated version.
func projectAppEngineSplit(value any) (Object, bool) {
	d := Obj(value)
	allocations := Obj(d["allocations"])
	if len(allocations) == 0 || len(allocations) > 1000 {
		return nil, false
	}
	clean := Object{}
	total := float64(0)
	for id, raw := range allocations {
		fraction, ok := raw.(float64)
		if !ok || !viewerAppEngineID.MatchString(id) || math.IsNaN(fraction) || math.IsInf(fraction, 0) || fraction <= 0 || fraction > 1 {
			return nil, false
		}
		total += fraction
		clean[id] = fraction
	}
	if math.Abs(total-1) > 1e-9 {
		return nil, false
	}
	out := Object{"allocations": clean}
	if raw, exists := d["shardBy"]; exists {
		mode, ok := raw.(string)
		if !ok || (mode != "UNSPECIFIED" && mode != "COOKIE" && mode != "IP" && mode != "RANDOM") {
			return nil, false
		}
		out["shardBy"] = mode
	}
	return out, true
}
