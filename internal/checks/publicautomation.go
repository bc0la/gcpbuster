package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var automationGrantResource = regexp.MustCompile(`^//(cloudtasks|cloudscheduler)\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9.:-]*/locations/[a-z][a-z0-9-]*/(queues|jobs)/([A-Za-z0-9_-]+)$`)

func publicAutomationCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || !public(s(val(a, "principal"))) {
		return nil
	}
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"cloudtasks.tasks.create", "cloudscheduler.jobs.run"}, "Automation", "Project-level task-creation or job-run grant only. Applicable queues/jobs, permission inheritance, conditional resource selectors and effective access must be evaluated separately; no individual queue/job is asserted accessible. Scheduler run does not change the existing job target or payload. Selecting a task OAuth/OIDC service account separately requires iam.serviceAccounts.actAs on that same-project account. Control-plane APIs require Google OAuth authentication; broad principals do not establish tokenless calls. No work was enqueued and no jobs or endpoints invoked.")
	}
	m := automationGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil {
		return nil
	}
	permission, title, detail := "", "", ""
	switch {
	case m[1] == "cloudtasks" && m[2] == "queues" && s(val(a, "resourceType")) == "cloudtasks.googleapis.com/Queue" && len(m[3]) <= 100 && !strings.Contains(m[3], "_"):
		permission = "cloudtasks.tasks.create"
		title = "Cloud Tasks queue grants task-creation capability to a broad principal"
		detail = "Task creation adds work to the existing queue, but queue routing and overrides constrain the target. Choosing a task OAuth/OIDC service account separately requires iam.serviceAccounts.actAs on that same-project account; enqueue permission alone does not establish authenticated dispatch, SSRF, arbitrary target access or service-account impersonation."
	case m[1] == "cloudscheduler" && m[2] == "jobs" && s(val(a, "resourceType")) == "cloudscheduler.googleapis.com/Job" && len(m[3]) <= 500:
		permission = "cloudscheduler.jobs.run"
		title = "Cloud Scheduler job has a broad-principal run capability observation"
		detail = "Run requests dispatch the existing configured job; this permission does not change its target, payload or authentication. Target success, downstream authority and the provenance/applicability of this scoped IAM observation are unverified. No native job-level IAM policy API is assumed."
	}
	if permission == "" || !has(arr(val(a, "permissions")), permission) {
		return nil
	}
	severity, status := "high", "no condition supplied on this observation"
	if condition := val(a, "condition"); condition != nil {
		severity, status = "medium", "condition supplied; not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	return result(severity, title, "Restrict broad automation permissions and review target configuration, conditions and independent target authentication; do not enqueue work or execute jobs to verify access.", inventory.Object{"resource": val(a, "resource"), "resource_type": val(a, "resourceType"), "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": permission, "condition": val(a, "condition"), "condition_status": status, "assessment": "Configured role permission observation only. These control-plane methods require Google OAuth authentication; allUsers and allAuthenticatedUsers do not prove tokenless API access. Deny, conditions and service perimeters remain unresolved. No tasks were created or dispatched and no jobs or targets were invoked. Inherited grants are not expanded. " + detail})
}

var projectCapabilityResource = regexp.MustCompile(`^//cloudresourcemanager\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9.:-]*$`)

// Project observations stay on the project: never synthesize child bindings.
func projectPublicCapability(a inventory.Asset, permissions []string, kind, detail string) []Result {
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "cloudresourcemanager.googleapis.com/Project" || !projectCapabilityResource.MatchString(s(val(a, "resource"))) || !public(s(val(a, "principal"))) {
		return nil
	}
	var out []Result
	severity, status := "high", "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		severity, status = "medium", "condition supplied; not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	for _, permission := range permissions {
		if !has(arr(val(a, "permissions")), permission) {
			continue
		}
		out = append(out, result(severity, kind+" capability granted to a broad principal at project scope", "Review the project-level role, conditions and intended audience, then verify applicable child-resource controls without executing the capability.", inventory.Object{"resource": val(a, "resource"), "resource_type": "cloudresourcemanager.googleapis.com/Project", "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": permission, "binding_scope": "project", "condition": val(a, "condition"), "condition_status": status, "assessment": "Observed project allow binding resolved from role definitions, not effective authorization. IAM deny, conditions and service perimeters remain unresolved. No child bindings were synthesized. " + detail})...)
	}
	return out
}
