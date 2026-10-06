package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var artifactNamedProject = regexp.MustCompile(`^//artifactregistry\.googleapis\.com/projects/([a-z][a-z0-9-]*)/locations/[a-z][a-z0-9-]*/repositories/[A-Za-z0-9][A-Za-z0-9._-]*$`)
var artifactUserServiceAccount = regexp.MustCompile(`^serviceAccount:[a-z][a-z0-9-]*@([a-z][a-z0-9-]*)\.iam\.gserviceaccount\.com$`)
var artifactServiceAgentName = regexp.MustCompile(`^serviceAccount:service-[0-9]+@`)

func artifactCrossProjectAccess(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "artifactregistry.googleapis.com/Repository" || !has(arr(val(a, "permissions")), "artifactregistry.repositories.downloadArtifacts") {
		return nil
	}
	repository := artifactNamedProject.FindStringSubmatch(s(val(a, "resource")))
	principal := artifactUserServiceAccount.FindStringSubmatch(s(val(a, "principal")))
	if len(repository) != 2 || len(principal) != 2 || repository[1] == principal[1] || strings.HasPrefix(principal[1], "gcp-sa-") || artifactServiceAgentName.MatchString(s(val(a, "principal"))) {
		return nil
	}
	status := "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		status = "condition supplied; applicability not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			status = "malformed condition; applicability unknown"
		}
	}
	return result("info", "Artifact repository grants download permission to a cross-project service account", "Validate intended cross-project integrations and the service account's ownership; review exact permissions and conditions before changing access.", inventory.Object{"resource": val(a, "resource"), "principal": val(a, "principal"), "repository_project_id": repository[1], "service_account_project_id": principal[1], "permission": "artifactregistry.repositories.downloadArtifacts", "roles": val(a, "roles"), "condition": val(a, "condition"), "condition_status": status, "assessment": "Exact repository allow binding and canonical named-project user-managed service-account identity only. Different projects may belong to the same organization; this is not external-organization, anonymous-access or malicious-sharing proof. Numeric project aliases, service agents, users/groups and project-level inherited grants are not classified by this indicator. Effective access, IAM deny, perimeters and artifact sensitivity remain unverified; no content or credentials were requested."})
}
