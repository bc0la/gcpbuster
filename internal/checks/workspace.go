package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"time"
)

func workspace2SV(a inventory.Asset, _ time.Time) []Result {
	if b(val(a, "suspended")) || b(val(a, "archived")) {
		return nil
	}
	var out []Result
	sev := "medium"
	if b(val(a, "isAdmin")) || b(val(a, "isDelegatedAdmin")) {
		sev = "high"
	}
	if isFalse(val(a, "isEnrolledIn2Sv")) {
		out = append(out, Result{sev, "Workspace user is not enrolled in 2-Step Verification", inventory.Object{"is_admin": val(a, "isAdmin"), "assessment": "review any externally enforced IdP MFA"}, "Require appropriate phishing-resistant MFA and enroll the user."})
	}
	if isFalse(val(a, "isEnforcedIn2Sv")) {
		out = append(out, Result{sev, "Workspace 2-Step Verification is not enforced for user", nil, "Review OU/group enforcement and any external IdP MFA controls."})
	}
	return out
}
func sensitiveScopes(v any) []string {
	var out []string
	for _, v := range arr(v) {
		scope := s(v)
		for _, p := range []string{"https://mail.google.com/", "https://www.googleapis.com/auth/gmail.", "https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.", "https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/apps.groups.settings"} {
			if strings.HasPrefix(scope, p) {
				out = append(out, scope)
				break
			}
		}
	}
	return out
}
func workspaceOAuth(a inventory.Asset, _ time.Time) []Result {
	scopes := sensitiveScopes(val(a, "scopes"))
	if len(scopes) == 0 {
		return nil
	}
	return result("medium", "OAuth application has sensitive Workspace or Cloud scopes", "Validate business need, publisher and exact scopes; revoke unused grants.", inventory.Object{"client_id": val(a, "clientId"), "scopes": scopes, "assessment": "grant inventory; trust or maliciousness not established"})
}
func workspaceAdmins(a inventory.Asset, _ time.Time) []Result {
	if a.Type == "workspace.googleapis.com/User" {
		if b(val(a, "isAdmin")) || b(val(a, "isDelegatedAdmin")) {
			return result("info", "Workspace administrator account", "Validate named owner, least privilege, MFA and emergency-access procedures.", inventory.Object{"super_admin": val(a, "isAdmin"), "delegated_admin": val(a, "isDelegatedAdmin"), "suspended": val(a, "suspended")})
		}
		return nil
	}
	if a.Type == "workspace.googleapis.com/RoleAssignment" {
		if s(val(a, "scopeType")) == "CUSTOMER" {
			return result("info", "Workspace role assignment spans the customer", "Review whether organizational-unit scoping is possible.", inventory.Object{"role_id": val(a, "roleId"), "assigned_to": val(a, "assignedTo")})
		}
		return nil
	}
	if b(val(a, "isSuperAdminRole")) {
		return result("info", "Workspace super-admin role present", "Review assigned principals and minimize standing super-admin access.", inventory.Object{"role_id": val(a, "roleId")})
	}
	var privileges []string
	for _, p := range arr(val(a, "rolePrivileges")) {
		name := s(obj(p)["privilegeName"])
		u := strings.ToUpper(name)
		if strings.Contains(u, "SECURITY") || strings.Contains(u, "ROLE") || strings.Contains(u, "USER") || strings.Contains(u, "GROUP") {
			privileges = append(privileges, name)
		}
	}
	if len(privileges) > 0 {
		return result("medium", "Workspace role contains sensitive administration privileges", "Review actual assignments and privilege scope; role definitions alone do not prove escalation.", inventory.Object{"role_id": val(a, "roleId"), "privileges": privileges})
	}
	return nil
}
func workspaceDWD(a inventory.Asset, _ time.Time) []Result {
	scopes := sensitiveScopes(val(a, "scopes"))
	sev := "info"
	if len(scopes) > 0 {
		sev = "high"
	}
	return result(sev, "Workspace domain-wide delegation grant requires review", "Reconcile authorized client IDs with known applications; minimize scopes and protect all service-account impersonation/key paths.", inventory.Object{"client_id": val(a, "clientId"), "sensitive_scopes": scopes, "assessment": "operator-supplied Admin console grant; service-account OAuth client ID alone is not proof of DWD"})
}
func workspaceMail(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if b(val(a, "autoForwarding", "enabled")) {
		out = append(out, Result{"medium", "Gmail automatic forwarding enabled", nil, "Validate forwarding destination ownership and business need; remove unauthorized forwarding."})
	}
	for _, v := range arr(val(a, "delegates")) {
		x := obj(v)
		if s(x["verificationStatus"]) == "accepted" {
			out = append(out, Result{"medium", "Gmail mailbox has an accepted delegate", inventory.Object{"delegate": x["delegateEmail"]}, "Review the delegate's authorization and remove stale access."})
		}
	}
	for _, v := range arr(val(a, "filters")) {
		if s(inventory.Get(obj(v), "action", "forward")) != "" {
			out = append(out, Result{"medium", "Gmail filter forwards messages", nil, "Review forwarding filters for unauthorized persistence."})
		}
	}
	return out
}
func workspaceGroups(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "workspace.googleapis.com/GroupSettings" {
		return nil
	}
	var out []Result
	if s(val(a, "whoCanViewGroup")) == "ANYONE_CAN_VIEW" {
		severity, title := "info", "Group permits public message viewing; archive contents are unverified"
		history := "unknown"
		if b(val(a, "isArchived")) || s(val(a, "isArchived")) == "true" {
			history = "enabled"
			severity = "high"
			title = "Group permits public message viewing with archiving enabled"
		} else if isFalse(val(a, "isArchived")) || s(val(a, "isArchived")) == "false" {
			history = "disabled_for_new_messages"
		}
		if b(val(a, "archiveOnly")) || s(val(a, "archiveOnly")) == "true" {
			history = "archive_only"
			severity = "high"
			title = "Archived group permits public message viewing"
		}
		out = append(out, Result{severity, title, inventory.Object{"setting": "whoCanViewGroup", "message_visibility": "ANYONE_CAN_VIEW", "conversation_history": history, "assessment": "Operator-supplied group settings only; no messages or membership were read. Disabled archiving does not remove previously archived messages. Public conversation visibility is not public membership-list access, membership or inherited IAM authority; actual archived content remains unverified."}, "Restrict conversation visibility where public archives are not intended and separately review retained messages and group membership controls."})
	}
	for _, spec := range []struct{ key, value, title, severity string }{
		{"whoCanJoin", "ANYONE_CAN_JOIN", "Group configures open joining; identity and tenant restrictions require review", "high"},
		{"whoCanPostMessage", "ANYONE_CAN_POST", "Anyone can post to the group", "medium"},
		{"allowExternalMembers", "true", "Group permits external members", "medium"},
	} {
		if strings.EqualFold(s(val(a, spec.key)), spec.value) || (spec.value == "true" && b(val(a, spec.key))) {
			out = append(out, Result{spec.severity, spec.title, inventory.Object{"setting": spec.key, "assessment": "Operator-supplied group settings only; actual membership and any IAM usage require correlation. Joining requires an eligible Google identity; tenant external-member policy and security/locked-group restrictions may prevent self-enrollment. No joining, posting or membership listing occurred."}, "Restrict group access to the intended audience, especially for groups used in IAM."})
		}
	}
	return out
}
func workspaceDrive(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "permissions")) {
		p := obj(v)
		if b(p["deleted"]) {
			continue
		}
		if s(p["type"]) == "anyone" {
			out = append(out, Result{"high", "Drive file or shared drive permits anyone access", inventory.Object{"role": p["role"], "discoverable": p["allowFileDiscovery"]}, "Remove anyone permissions or explicitly approve the public share."})
		}
	}
	return out
}
