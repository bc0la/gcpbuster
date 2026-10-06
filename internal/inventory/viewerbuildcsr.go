package inventory

import (
	"regexp"
	"strings"
)

const viewerCSRMirrorFields = "name,mirrorConfig(url)"

var viewerCSRRepoRef = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/repos/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)

func buildCSRRequest(a Asset, d Object) buildRepositoryRequest {
	project := strings.Split(strings.TrimPrefix(a.Name, "//cloudbuild.googleapis.com/"), "/")[1]
	if raw, exists := d["projectId"]; exists {
		p, ok := raw.(string)
		if !ok {
			return buildRepositoryRequest{}
		}
		if p != "" {
			project = p
		}
	}
	repo, ok := d["repoName"].(string)
	if !ok || len(repo) > 512 || !viewerResourceName.MatchString(project) {
		return buildRepositoryRequest{}
	}
	ref := "projects/" + project + "/repos/" + repo
	if !validCSRRepoRef(ref) {
		return buildRepositoryRequest{}
	}
	return buildRepositoryRequest{host: "sourcerepo.googleapis.com", version: "v1", kind: "clone_uri", field: "mirrorConfig(url)", ref: ref, config: d, binding: BuildTrustDigest(a.Name + "\x00triggerTemplate\x00" + ref)}
}

func validCSRRepoRef(ref string) bool {
	if len(ref) > 1024 || !viewerCSRRepoRef.MatchString(ref) {
		return false
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// BuildTriggerCSRMirrorConfigured accepts only an observation bound to the
// current native CSR trigger reference. It does not establish mirror freshness,
// working upstream credentials/webhooks, contributor authority or execution.
func BuildTriggerCSRMirrorConfigured(a Asset) bool {
	req := buildRepositoryRequestFor(a)
	return req.host == "sourcerepo.googleapis.com" && BuildTriggerRepositoryIdentityDigest(a) != "" && Str(Get(a.Resource.Data, "_gcpbusterResolvedBuildRepository", "resolution_source")) == "csr_mirror_metadata"
}
