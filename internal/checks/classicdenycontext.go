package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
)

func classicDenyContextEvidence(raw any, project string, allowPriority int) inventory.Object {
	out := inventory.Object{"status": "unknown", "snapshot_coverage": "unknown", "effective_admission": "unknown", "denies": []any{}}
	d := obj(raw)
	if d["effective_admission"] != "unknown" {
		return out
	}
	status := s(d["status"])
	if status != "unknown" && status != "observed_overlap" && status != "definitely_shadowed_by_observed_classic_deny" {
		return out
	}
	coverage := s(d["snapshot_coverage"])
	if coverage != "completed" && coverage != "unknown" {
		return out
	}
	rows, ok := d["denies"].([]any)
	if !ok || len(rows) > 256 {
		return out
	}
	safe := []any{}
	seen := map[string]bool{}
	re := regexp.MustCompile(`^//compute\.googleapis\.com/projects/` + regexp.QuoteMeta(project) + `/global/firewalls/[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	for _, raw := range rows {
		r := obj(raw)
		name := s(r["firewall_resource"])
		priority, ok := ingressContextInt(r["priority"], 65535)
		if !ok || priority > allowPriority || !re.MatchString(name) || seen[name] {
			return out
		}
		seen[name] = true
		safe = append(safe, inventory.Object{"firewall_resource": name, "priority": priority})
	}
	if status != "unknown" && len(safe) == 0 {
		return out
	}
	if status == "definitely_shadowed_by_observed_classic_deny" && coverage != "completed" {
		return out
	}
	out["status"], out["snapshot_coverage"], out["denies"] = status, coverage, safe
	out["assessment"] = "This observed classic deny context applies only to the matched allow rule configuration. It does not establish effective blocking; higher-priority alternative allows, hierarchical/network policies and runtime traffic remain unverified."
	return out
}
