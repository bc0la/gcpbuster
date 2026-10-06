package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func orgPolicyGuardrails(a inventory.Asset, _ time.Time) []Result {
	id := s(val(a, "constraint"))
	spec := obj(val(a, "spec"))
	if !b(val(a, "effective")) || !inventory.ValidEffectiveOrgSpec(id, spec) {
		return nil
	}
	rule := obj(arr(spec["rules"])[0])
	unrestricted := isFalse(rule["enforce"]) || b(rule["allowAll"])
	if !unrestricted {
		return nil
	}
	return result("medium", "Selected organization-policy guardrail is not restricting this scope", "Review whether this guardrail should be enforced. Check managed/custom constraints, resource-level policies and workload compatibility before making changes.", inventory.Object{"constraint": id, "scope": val(a, "scope"), "effective_rule": rule, "assessment": "Server-evaluated selected constraint is not restrictive at this container; other constraints and runtime controls may still block the operation. Existing resources are not proven noncompliant."})
}
