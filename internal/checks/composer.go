package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
	"sort"
	"time"
)

// composerNetwork reviews explicit environment metadata, as enumerated by
// gcp-composer-enum.md. It does not execute DAGs, export storage objects, or
// access Airflow. Field semantics are documented at:
// https://docs.cloud.google.com/composer/docs/reference/rest/v1/projects.locations.environments
func composerNetwork(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	// A global allowlist entry is network admission, not anonymous Airflow
	// authorization. An omitted/empty policy is intentionally unknown here.
	ranges := map[string]bool{}
	for _, raw := range arr(val(a, "config", "webServerNetworkAccessControl", "allowedIpRanges")) {
		value := s(obj(raw)["value"])
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Bits() == 0 && prefix == prefix.Masked() {
			ranges[prefix.String()] = true
		}
	}
	ordered := make([]string, 0, len(ranges))
	for value := range ranges {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	for _, value := range ordered {
		out = append(out, Result{"medium", "Composer Airflow webserver admits an internet-wide network", inventory.Object{"network": value, "assessment": "Explicit webserver network admission only; IAM, Airflow authentication and other access controls still apply. Neither anonymous access nor actual reachability was tested."}, "Restrict the webserver allowlist to required client networks where appropriate and review authenticated access separately."})
	}
	private := obj(val(a, "config", "privateEnvironmentConfig"))
	modern, modernPresent := private["networkingType"]
	legacy, legacyPresent := private["enablePrivateEnvironment"]
	public := false
	if modernPresent {
		if mode, ok := modern.(string); ok && mode == "PUBLIC" {
			public = true
			if legacyPresent {
				v, valid := legacy.(bool)
				public = valid && !v // Conflict/malformed legacy setting is unknown.
			}
		}
	} else if v, ok := legacy.(bool); ok {
		public = !v
	}
	if public {
		out = append(out, Result{"info", "Composer environment explicitly uses public networking", inventory.Object{"assessment": "Environment networking configuration permits internet connectivity; this does not establish public worker IP allocation, inbound reachability, unauthenticated Airflow access or broad IAM permissions."}, "Review whether the workload requires public networking or can use private connectivity; assess worker ingress and webserver authorization separately."})
	}
	return out
}
