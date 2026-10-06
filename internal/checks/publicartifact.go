package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var artifactGrantResource = regexp.MustCompile(`^//artifactregistry\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/locations/[a-z][a-z0-9-]*/repositories/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// publicArtifactAccess is the narrow configured-download counterpart to
// BezosBuster's public_ecr repository indicator. An arbitrary public metadata
// role is not artifact-read access. Inputs must be actual direct bindings joined
// to supplied role definitions, not unassigned roles or a repository's existence.
// https://docs.cloud.google.com/artifact-registry/docs/access-control
func publicArtifactAccess(a inventory.Asset, _ time.Time) []Result {
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"artifactregistry.repositories.downloadArtifacts"}, "Artifact download", "Project-level download permission only; applicable repositories, inheritance and repository controls require separate assessment. No packages, manifests or layers were requested.")
	}
	if a.Type != inventory.PermissionGrantType || s(val(a, "resourceType")) != "artifactregistry.googleapis.com/Repository" || !artifactGrantResource.MatchString(s(val(a, "resource"))) {
		return nil
	}
	principal := s(val(a, "principal"))
	if principal != "allUsers" && principal != "allAuthenticatedUsers" {
		return nil
	}
	download := false
	for _, permission := range arr(val(a, "permissions")) {
		if s(permission) == "artifactregistry.repositories.downloadArtifacts" {
			download = true
		}
	}
	if !download {
		return nil
	}
	title := "Repository grants artifact-download capability to all users"
	audience := "allUsers includes anonymous callers; actual unauthenticated download was not tested"
	if principal == "allAuthenticatedUsers" {
		title = "Repository grants artifact-download capability to any Google-authenticated identity"
		audience = "allAuthenticatedUsers is broader than the organization, but does not include anonymous callers"
	}
	conditionStatus := "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		conditionStatus = "condition supplied; expression was not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			conditionStatus = "malformed condition evidence; effective grant applicability is unknown"
		}
	}
	return result("medium", title, "Review whether this repository intentionally distributes public artifacts; remove broad download grants where inappropriate. Validate effective authorization and artifact sensitivity separately.", inventory.Object{
		"resource": val(a, "resource"), "resource_type": val(a, "resourceType"), "principal": principal, "roles": val(a, "roles"), "permission": "artifactregistry.repositories.downloadArtifacts", "condition": val(a, "condition"), "condition_status": conditionStatus, "audience": audience,
		"assessment": "Configured direct repository grant resolved from role definitions only. IAM deny, conditions, service perimeter and other controls may restrict effective access. No repository content, image manifest, layer or package was requested; repository mode, virtual upstream access and artifact existence/sensitivity were not established. Inherited project/folder/organization grants are not expanded by this indicator.",
	})
}
