package inventory

import (
	"crypto/sha256"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
	"regexp"
	"sort"
	"strings"
)

// GitHubRepositoryMetadataType is an optional supplied snapshot schema, not a
// Google Cloud resource or a live GitHub collection method. Name is
// //github.com/OWNER/REPOSITORY; data contains matching owner/name and explicit
// visibility public/private/internal. No credentials or provider calls needed.
const GitHubRepositoryMetadataType = "gcpbuster.googleapis.com/GitHubRepositoryMetadata"

var buildTrustTrigger = regexp.MustCompile(`^//cloudbuild\.googleapis\.com/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/triggers/[A-Za-z0-9_-]+$`)
var buildTrustAccount = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/serviceAccounts/([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com)$`)
var buildTrustOwner = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
var buildTrustRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var buildTrustProjectScope = regexp.MustCompile(`^//cloudresourcemanager\.googleapis\.com/projects/[A-Za-z0-9_-]+$`)
var buildTrustAccountScope = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[A-Za-z0-9_-]+/serviceAccounts/[A-Za-z0-9_.@+-]+$`)
var buildTrustResourceScope = regexp.MustCompile(`^//[a-z][a-z0-9]*\.googleapis\.com/[A-Za-z0-9_/-]+$`)

func buildTrustScope(resource string) string {
	if buildTrustProjectScope.MatchString(resource) {
		return "project"
	}
	if buildTrustAccountScope.MatchString(resource) {
		return "service_account"
	}
	if buildTrustResourceScope.MatchString(resource) {
		return "resource"
	}
	return "unknown"
}

func BuildTriggerServiceAccount(a Asset) string {
	if a.Type != "cloudbuild.googleapis.com/BuildTrigger" || !buildTrustTrigger.MatchString(a.Name) {
		return ""
	}
	m := buildTrustAccount.FindStringSubmatch(Str(a.Resource.Data["serviceAccount"]))
	if m == nil {
		return ""
	}
	return m[1]
}

func BuildTriggerGitHubRepository(a Asset) string {
	if a.Type != "cloudbuild.googleapis.com/BuildTrigger" || !buildTrustTrigger.MatchString(a.Name) {
		return ""
	}
	d := Obj(a.Resource.Data["github"])
	// GitHub Enterprise identities are not github.com identities.
	if v, present := d["enterpriseConfigResourceName"]; present {
		text, valid := v.(string)
		if !valid || text != "" {
			return ""
		}
	}
	for _, field := range []string{"repositoryEventConfig", "developerConnectEventConfig", "bitbucketServerTriggerConfig", "triggerTemplate", "pubsubConfig", "webhookConfig"} {
		if _, exists := a.Resource.Data[field]; exists {
			return ""
		}
	}
	return buildGitHubIdentity(Str(d["owner"]), Str(d["name"]))
}

func buildGitHubIdentity(owner, repo string) string {
	if !buildTrustOwner.MatchString(owner) || !buildTrustRepo.MatchString(repo) || repo == "." || repo == ".." {
		return ""
	}
	return "//github.com/" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
}

func BuildTrustDigest(value string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(value))) }

// CorrelateBuildTrustContext joins explicit trigger identities with direct
// grants and optional supplied GitHub visibility. Nothing is fetched/executed;
// bindings keep their individual scope and unevaluated condition status.
func CorrelateBuildTrustContext(out *Snapshot) {
	for i := range out.Assets {
		if out.Assets[i].Type == "cloudbuild.googleapis.com/BuildTrigger" {
			delete(out.Assets[i].Resource.Data, "_gcpbusterBuildTrust")
		}
	}
	if len(out.Assets) > 100000 {
		out.Coverage = append(out.Coverage, Coverage{Source: "build-trust-context", Status: "incomplete", Error: "Snapshot exceeds metadata correlation bound"})
		return
	}
	repos, conflicts := map[string]string{}, map[string]bool{}
	grants := map[string][]any{}
	truncated := map[string]bool{}
	triggerIdentities := map[string]string{}
	permissionBudget := 1000000
	for _, a := range out.Assets {
		d := a.Resource.Data
		if a.Type == "cloudbuild.googleapis.com/BuildTrigger" {
			identity := BuildTriggerServiceAccount(a) + "\x00" + BuildTriggerRepositoryIdentityDigest(a)
			if old, exists := triggerIdentities[a.Name]; exists && old != identity {
				conflicts[a.Name] = true
			}
			triggerIdentities[a.Name] = identity
		}
		if a.Type == GitHubRepositoryMetadataType || a.Type == RepositoryTrustMetadataType {
			identity := buildGitHubIdentity(Str(d["owner"]), Str(d["name"]))
			visibility := Str(d["visibility"])
			nameMatches := strings.ToLower(a.Name) == identity
			namedDigest := BuildTrustDigest(strings.ToLower(a.Name))
			if a.Type == RepositoryTrustMetadataType {
				identity = RepositoryTrustIdentity(Obj(d["identity"]))
				namedDigest = strings.TrimPrefix(a.Name, "//gcpbuster.googleapis.com/repositoryTrust/")
				nameMatches = a.Name == "//gcpbuster.googleapis.com/repositoryTrust/"+BuildTrustDigest(identity)
			}
			if identity == "" || !nameMatches || (visibility != "public" && visibility != "private" && visibility != "internal") {
				conflicts[namedDigest] = true
				continue
			}
			identity = BuildTrustDigest(identity)
			if old, ok := repos[identity]; ok && old != visibility {
				conflicts[identity] = true
			}
			repos[identity] = visibility
		}
		if a.Type != PermissionGrantType {
			continue
		}
		principal := Str(d["principal"])
		if !strings.HasPrefix(principal, "serviceAccount:") || !serviceAccountEmail.MatchString(strings.TrimPrefix(principal, "serviceAccount:")) {
			continue
		}
		if len(grants[principal]) >= 100 {
			truncated[principal] = true
			continue
		}
		permissions, ok := d["permissions"].([]any)
		if !ok || len(permissions) > 10000 {
			truncated[principal] = true
			continue
		}
		permissionBudget -= len(permissions)
		if permissionBudget < 0 {
			out.Coverage = append(out.Coverage, Coverage{Source: "build-trust-context", Status: "incomplete", Error: "Permission metadata exceeds bounded correlation budget"})
			return
		}
		selected := map[string]bool{}
		for _, p := range permissions {
			name := Str(p)
			rating, ok := permissioncatalog.Severity(name)
			if ok && (rating == "high" || rating == "critical") {
				selected[name] = true
			}
		}
		if len(selected) == 0 || Str(d["resource"]) == "" || len(Str(d["resource"])) > 2048 {
			continue
		}
		names := make([]string, 0, len(selected))
		for p := range selected {
			names = append(names, p)
		}
		sort.Strings(names)
		condition := "not_supplied"
		if raw, exists := d["condition"]; exists && raw != nil {
			condition = "supplied_unevaluated"
			if strings.TrimSpace(Str(Obj(raw)["expression"])) == "" {
				condition = "malformed_unknown"
			}
		}
		values := make([]any, len(names))
		for i, n := range names {
			values[i] = n
		}
		grants[principal] = append(grants[principal], Object{"grant_resource_digest": BuildTrustDigest(Str(d["resource"])), "scope_kind": buildTrustScope(Str(d["resource"])), "permissions": values, "condition_status": condition})
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "cloudbuild.googleapis.com/BuildTrigger" || !buildTrustTrigger.MatchString(a.Name) {
			continue
		}
		marker := Object{"repository_visibility": "unknown", "identity_status": "unknown", "basis": "observed_configuration_and_optional_supplied_repository_metadata"}
		if conflicts[a.Name] {
			a.Resource.Data["_gcpbusterBuildTrust"] = marker
			continue
		}
		if repo := BuildTriggerRepositoryIdentityDigest(*a); repo != "" && !conflicts[repo] && repos[repo] != "" {
			marker["repository_visibility"] = repos[repo]
			marker["repository_digest"] = repo
			marker["repository_basis"] = "supplied_metadata_not_live_verified"
		}
		if email := BuildTriggerServiceAccount(*a); email != "" {
			marker["identity_status"] = "explicit_trigger_service_account"
			marker["service_account"] = email
			rows := grants["serviceAccount:"+email]
			sort.Slice(rows, func(i, j int) bool { return fmt.Sprint(rows[i]) < fmt.Sprint(rows[j]) })
			marker["high_impact_direct_grants"] = rows
			marker["grants_truncated"] = truncated["serviceAccount:"+email]
		}
		a.Resource.Data["_gcpbusterBuildTrust"] = marker
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "build-trust-context", Status: "notice", Error: "Explicit trigger service-account emails and direct resolved grants only; no default/inline-build identity, effective authorization or execution inferred. Repository visibility only from matching supplied GitHubRepositoryMetadata or RepositoryTrustMetadata; other families require selected control-plane reference metadata. No live repository authority, contributor permissions, credential scopes, event filters or actual PR execution verified."})
}
