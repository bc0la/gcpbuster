package inventory

import (
	"context"
	"fmt"
	"strings"
)

const EffectiveOrgPolicyType = "gcpbuster.googleapis.com/EffectiveOrgPolicy"

// Selected legacy guardrails are independent controls, not a complete constraint
// catalog. Newer managed/custom constraints can provide additional restrictions.
var OrgPolicyConstraints = []string{
	"iam.disableServiceAccountKeyCreation",
	"iam.disableServiceAccountKeyUpload",
	"iam.disableCrossProjectServiceAccountUsage",
	"iam.automaticIamGrantsForDefaultServiceAccounts",
	"storage.publicAccessPrevention",
	"storage.uniformBucketLevelAccess",
	"compute.disableSerialPortAccess",
	"compute.requireOsLogin",
	"appengine.disableCodeDownload",
	"iam.allowedPolicyMemberDomains",
	"compute.vmExternalIpAccess",
}

func knownOrgConstraint(id string) bool {
	for _, c := range OrgPolicyConstraints {
		if c == id {
			return true
		}
	}
	return false
}

// ValidEffectiveOrgSpec accepts only server-evaluated shapes used by our checks.
// Empty/conditional/reset responses never become evidence of disabled enforcement.
func ValidEffectiveOrgSpec(id string, spec Object) bool {
	if !knownOrgConstraint(id) || spec == nil || Bool(spec["reset"]) {
		return false
	}
	rules := List(spec["rules"])
	if len(rules) != 1 {
		return false
	}
	rule := Obj(rules[0])
	if rule == nil || rule["condition"] != nil {
		return false
	}
	if id == "iam.allowedPolicyMemberDomains" || id == "compute.vmExternalIpAccess" {
		variants := 0
		if Bool(rule["allowAll"]) {
			variants++
		}
		if Bool(rule["denyAll"]) {
			variants++
		}
		if values := Obj(rule["values"]); values != nil {
			count := 0
			for _, key := range []string{"allowedValues", "deniedValues"} {
				if raw, exists := values[key]; exists {
					xs, ok := raw.([]any)
					if !ok {
						return false
					}
					for _, v := range xs {
						if s, ok := v.(string); !ok || s == "" {
							return false
						}
						count++
					}
				}
			}
			if count == 0 {
				return false
			}
			variants++
		}
		return variants == 1 && rule["enforce"] == nil
	}
	_, ok := rule["enforce"].(bool)
	return ok && rule["allowAll"] == nil && rule["denyAll"] == nil && rule["values"] == nil
}

func (c *Client) CollectOrgPolicies(ctx context.Context, snap *Snapshot, scopes []string) {
	seen := map[string]bool{}
	for _, scope := range scopes {
		if seen[scope] {
			continue
		}
		seen[scope] = true
		if !logScopePattern.MatchString(scope) {
			snap.record("org-policy:scope", 0, fmt.Errorf("invalid resource container"))
			continue
		}
		for _, constraint := range OrgPolicyConstraints {
			if err := ctx.Err(); err != nil {
				snap.record("org-policy:"+scope, 0, err)
				return
			}
			name := scope + "/policies/" + constraint
			policy, err := c.get(ctx, "https://orgpolicy.googleapis.com/v2/"+name+":getEffectivePolicy", nil)
			if err != nil {
				snap.record("org-policy:"+name, 0, err)
				continue
			}
			// Project-ID requests legitimately return project-number names.
			returned := Str(policy["name"])
			prefix := strings.TrimSuffix(returned, "/policies/"+constraint)
			validName := strings.HasSuffix(returned, "/policies/"+constraint) && logScopePattern.MatchString(prefix)
			if strings.HasPrefix(scope, "projects/") {
				validName = validName && strings.HasPrefix(prefix, "projects/")
			} else {
				validName = validName && prefix == scope
			}
			if !validName || !ValidEffectiveOrgSpec(constraint, Obj(policy["spec"])) {
				snap.record("org-policy:"+name, 0, fmt.Errorf("missing or unsupported effective organization-policy response"))
				continue
			}
			a := NewAsset("//orgpolicy.googleapis.com/"+name, EffectiveOrgPolicyType, Object{"constraint": constraint, "scope": scope, "effective": true, "spec": policy["spec"], "returnedName": returned})
			a.Ancestors = []string{scope}
			snap.Assets = append(snap.Assets, a)
			snap.record("org-policy:"+name, 1, nil)
		}
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "org-policy:limitations", Status: "notice", Error: "Selected effective legacy constraints only; newer managed/custom constraints, tags on child resources and other access controls may impose additional restrictions. Non-enforcement is not proof of effective access or exploitability."})
}
