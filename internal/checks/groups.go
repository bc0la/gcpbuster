package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func groupIAMPaths(a inventory.Asset, _ time.Time) []Result {
	base := inventory.Object{"group": val(a, "groupEmail"), "role": val(a, "role"), "bound_resource": val(a, "boundResource"), "iam_condition": val(a, "condition"), "assessment": "Correlated metadata, not effective authorization. Tenant join policy, security/locked-group restrictions, membership-change authority and IAM conditions still apply."}
	groupType := "unknown"
	restricted := false
	if s(val(a, "cloudIdentity", "status")) == "observed" {
		labels := obj(val(a, "cloudIdentity", "labels"))
		for _, key := range []string{"cloudidentity.googleapis.com/groups.security", "cloudidentity.googleapis.com/groups.locked", "cloudidentity.googleapis.com/groups.dynamic"} {
			if value, present := labels[key]; present {
				if text, ok := value.(string); ok && text == "" {
					restricted = true
				}
			}
		}
		if restricted {
			groupType = "observed_restricted_group"
		} else if text, ok := labels["cloudidentity.googleapis.com/groups.discussion_forum"].(string); ok && text == "" {
			groupType = "observed_discussion_group"
		}
	}
	base["group_type_assessment"] = groupType
	base["evidence_origin"] = "supplied_offline_cloud_identity_metadata"
	var out []Result
	join := s(val(a, "settings", "whoCanJoin"))
	if join == "ANYONE_CAN_JOIN" || join == "ALL_IN_DOMAIN_CAN_JOIN" {
		e := inventory.Object{}
		for k, v := range base {
			e[k] = v
		}
		e["who_can_join"] = join
		e["allow_external_members"] = val(a, "settings", "allowExternalMembers")
		severity, title := "high", "IAM-bound group has a self-service join setting"
		if restricted {
			severity, title = "info", "IAM-bound restricted group has a self-service join setting requiring reconciliation"
		}
		out = append(out, Result{severity, title, e, "Review join eligibility and effective group-type/tenant restrictions. Security/locked groups require appropriate administrative membership authority; dynamic membership follows its query. A join setting alone is not a self-enrollment bypass. Restrict self-service enrollment for ordinary groups granting sensitive cloud access."})
	}
	for _, raw := range arr(val(a, "membership", "members")) {
		m := obj(raw)
		role := s(m["role"])
		if role != "OWNER" && role != "MANAGER" {
			continue
		}
		if status := s(m["status"]); status != "" && status != "ACTIVE" {
			continue
		}
		e := inventory.Object{}
		for k, v := range base {
			e[k] = v
		}
		e["member_id"] = m["id"]
		e["member_email"] = m["email"]
		e["group_role"] = role
		e["membership_complete"] = val(a, "membership", "complete")
		severity := "medium"
		if restricted {
			severity = "info"
		}
		out = append(out, Result{severity, "IAM-bound group has a membership-management principal", e, "Verify the principal's effective ability to manage membership/settings and whether that authority can alter access to the group's bound cloud resources. OWNER/MANAGER is not sufficient proof of membership-change authority for security, locked or dynamic groups. Remove stale ownership or management roles."})
	}
	return out
}
