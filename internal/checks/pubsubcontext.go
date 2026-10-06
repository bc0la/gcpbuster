package checks

import "github.com/bc0la/gcpbuster/internal/inventory"

func pubsubDeliveryEvidence(a inventory.Asset) inventory.Object {
	d := obj(val(a, "_gcpbusterPubSubDelivery"))
	m := pubsubGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "pubsub.googleapis.com/Topic" || m == nil || m[1] != "topics" || d["topic"] != val(a, "resource") || d["coverage"] != "observed_subset_not_complete" {
		return nil
	}
	out := inventory.Object{"coverage": "observed_subset_not_complete"}
	sum := 0
	for _, key := range []string{"observed_subscriptions", "push", "bigquery", "storage", "bigtable", "unknown", "detached", "state_unknown", "resource_error"} {
		n, ok := apigeeStepCount(d[key])
		if !ok || n > 100000 {
			return nil
		}
		out[key] = n
		if key == "push" || key == "bigquery" || key == "storage" || key == "bigtable" || key == "unknown" || key == "detached" {
			sum += n
		}
	}
	total := out["observed_subscriptions"].(int)
	if total == 0 || sum != total || out["state_unknown"].(int)+out["resource_error"].(int) > total {
		return nil
	}
	out["assessment"] = "Exact same-project observed subscription configuration subset only, not delivery or downstream execution. Detached observations are separate; absent delivery fields are unknown, not assumed pull. Filters, transformations, subscription/destination permissions, endpoint authorization and current health are not evaluated. No messages were published, pulled, acknowledged or read; no endpoints or destinations contacted."
	return out
}
