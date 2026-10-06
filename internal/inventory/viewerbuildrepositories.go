package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const RepositoryTrustMetadataType = "gcpbuster.googleapis.com/RepositoryTrustMetadata"

var buildRepositoryRef = regexp.MustCompile(`^projects/([A-Za-z0-9_-]+)/locations/([a-z][a-z0-9-]*)/connections/([A-Za-z0-9_-]+)/repositories/([A-Za-z0-9_-]+)$`)
var buildLinkRef = regexp.MustCompile(`^projects/([A-Za-z0-9_-]+)/locations/([a-z][a-z0-9-]*)/connections/([A-Za-z0-9_-]+)/gitRepositoryLinks/([A-Za-z0-9_-]+)$`)
var buildEnterpriseRef = regexp.MustCompile(`^projects/([A-Za-z0-9_-]+)/(?:locations/[a-z][a-z0-9-]*/)?githubEnterpriseConfigs/[A-Za-z0-9_-]+$`)
var buildBitbucketRef = regexp.MustCompile(`^projects/([A-Za-z0-9_-]+)/locations/[a-z][a-z0-9-]*/bitbucketServerConfigs/[A-Za-z0-9_-]+$`)
var buildProviderSegment = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,255}$`)
var buildIdentityDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func BuildTriggerRepositoryIdentityDigest(a Asset) string {
	if repo := BuildTriggerGitHubRepository(a); repo != "" {
		return BuildTrustDigest(repo)
	}
	req := buildRepositoryRequestFor(a)
	m := Obj(a.Resource.Data["_gcpbusterResolvedBuildRepository"])
	if req.binding == "" || Str(m["binding_digest"]) != req.binding || Str(m["kind"]) != req.kind || Str(m["basis"]) != "selected_control_plane_reference_metadata" || !buildIdentityDigest.MatchString(Str(m["identity_digest"])) {
		return ""
	}
	return Str(m["identity_digest"])
}

type buildRepositoryRequest struct {
	kind, ref, host, version, field, binding string
	config                                   Object
}

func buildRepositoryRequestFor(a Asset) buildRepositoryRequest {
	if a.Type != "cloudbuild.googleapis.com/BuildTrigger" || !buildTrustTrigger.MatchString(a.Name) {
		return buildRepositoryRequest{}
	}
	family := ""
	var d Object
	for _, key := range []string{"github", "repositoryEventConfig", "developerConnectEventConfig", "bitbucketServerTriggerConfig", "triggerTemplate", "pubsubConfig", "webhookConfig"} {
		if raw, exists := a.Resource.Data[key]; exists {
			if family != "" {
				return buildRepositoryRequest{}
			}
			family = key
			d = Obj(raw)
		}
	}
	req := buildRepositoryRequest{host: "cloudbuild.googleapis.com", version: "v1", config: d}
	var matcher *regexp.Regexp
	switch family {
	case "triggerTemplate":
		return buildCSRRequest(a, d)
	case "repositoryEventConfig":
		req.kind = "clone_uri"
		req.ref = Str(d["repository"])
		req.field = "remoteUri"
		req.version = "v2"
		matcher = buildRepositoryRef
	case "developerConnectEventConfig":
		req.kind = "clone_uri"
		req.ref = Str(d["gitRepositoryLink"])
		req.field = "cloneUri"
		req.host = "developerconnect.googleapis.com"
		matcher = buildLinkRef
	case "github":
		req.kind = "github_enterprise"
		req.ref = Str(d["enterpriseConfigResourceName"])
		req.field = "hostUrl"
		matcher = buildEnterpriseRef
	case "bitbucketServerTriggerConfig":
		req.kind = "bitbucket_server"
		req.ref = Str(d["bitbucketServerConfigResource"])
		req.field = "hostUri"
		matcher = buildBitbucketRef
	default:
		return buildRepositoryRequest{}
	}
	if !matcher.MatchString(req.ref) {
		return buildRepositoryRequest{}
	}
	req.binding = BuildTrustDigest(a.Name + "\x00" + family + "\x00" + req.ref + "\x00" + Str(d["owner"]) + "\x00" + Str(d["name"]) + "\x00" + Str(d["projectKey"]) + "\x00" + Str(d["repoSlug"]))
	return req
}

// BuildTriggerRepositoryBinding binds derived observations to an exact trigger
// reference. It does not resolve an opaque reference into a provider URL.
func BuildTriggerRepositoryBinding(a Asset) string { return buildRepositoryRequestFor(a).binding }

func viewerBuildRepositoryFields(host, path string) string {
	if host == "sourcerepo.googleapis.com" && strings.HasPrefix(path, "/v1/") && validCSRRepoRef(strings.TrimPrefix(path, "/v1/")) {
		return viewerCSRMirrorFields
	}
	if host == "developerconnect.googleapis.com" && buildLinkRef.MatchString(strings.TrimPrefix(path, "/v1/")) && strings.HasPrefix(path, "/v1/") {
		return "name,cloneUri"
	}
	if host != "cloudbuild.googleapis.com" {
		return ""
	}
	if strings.HasPrefix(path, "/v2/") && buildRepositoryRef.MatchString(strings.TrimPrefix(path, "/v2/")) {
		return "name,remoteUri"
	}
	if strings.HasPrefix(path, "/v1/") {
		if buildEnterpriseRef.MatchString(strings.TrimPrefix(path, "/v1/")) {
			return "name,hostUrl"
		}
		if buildBitbucketRef.MatchString(strings.TrimPrefix(path, "/v1/")) {
			return "name,hostUri"
		}
	}
	return ""
}

// RepositoryTrustIdentity validates the explicitly supplied provider identity.
// URLs are parsed, never fetched. SSH/scp forms and ambiguous encoded paths are
// deliberately unsupported. Bitbucket uses a tuple, not a guessed clone URL.
func RepositoryTrustIdentity(d Object) string {
	kind := Str(d["kind"])
	if kind == "clone_uri" {
		uri := buildRepositoryURL(Str(d["uri"]), false)
		if uri == "" {
			return ""
		}
		u, _ := url.Parse(uri)
		if u.Host == "github.com" {
			p := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
			if len(p) == 2 {
				return buildGitHubIdentity(p[0], strings.TrimSuffix(p[1], ".git"))
			}
		}
		return "clone_uri\x00" + uri
	}
	host := buildRepositoryURL(Str(d["hostUri"]), true)
	if host == "" {
		return ""
	}
	if kind == "github_enterprise" {
		owner, name := Str(d["owner"]), Str(d["name"])
		if buildGitHubIdentity(owner, name) == "" {
			return ""
		}
		return kind + "\x00" + host + "\x00" + strings.ToLower(owner) + "\x00" + strings.ToLower(name)
	}
	if kind == "bitbucket_server" {
		project, repo := Str(d["projectKey"]), Str(d["repoSlug"])
		if !buildProviderSegment.MatchString(project) || !buildProviderSegment.MatchString(repo) || project == "." || project == ".." || repo == "." || repo == ".." {
			return ""
		}
		return kind + "\x00" + host + "\x00" + project + "\x00" + repo
	}
	return ""
}

func buildRepositoryURL(raw string, hostOnly bool) string {
	if len(raw) > 2048 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(raw, "%\\\r\n\t") {
		return ""
	}
	host, valid := DNSLookupName(u.Host)
	if !valid || strings.Contains(u.Host, ":") {
		return ""
	}
	path := u.Path
	if hostOnly {
		path = strings.TrimSuffix(path, "/")
	}
	if !hostOnly && (path == "" || !strings.HasPrefix(path, "/")) {
		return ""
	}
	if path != "" {
		for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			if !buildProviderSegment.MatchString(part) || part == "." || part == ".." {
				return ""
			}
		}
	}
	return "https://" + host + path
}

// CollectViewerBuildRepositoryReferences reads only control-plane metadata for
// explicitly referenced, in-scope connections/repositories. No clone, token,
// webhook, branch or provider endpoint request is made.
func (c *Client) CollectViewerBuildRepositoryReferences(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-build-references", 0, fmt.Errorf("invalid project scope"))
		return
	}
	// Clear every in-scope prior derived observation before bounded traversal;
	// hitting the request limit must not preserve stale supplied resolutions.
	for i := range out.Assets {
		a := &out.Assets[i]
		p := strings.Split(strings.TrimPrefix(a.Name, "//cloudbuild.googleapis.com/"), "/")
		if a.Type == "cloudbuild.googleapis.com/BuildTrigger" && len(p) == 6 && p[0] == "projects" && (p[1] == projectID || "projects/"+p[1] == number) {
			delete(a.Resource.Data, "_gcpbusterResolvedBuildRepository")
		}
	}
	if len(out.Assets) > 100000 {
		out.record("viewer-build-references", 0, fmt.Errorf("snapshot exceeds reference collection bound"))
		return
	}
	cache := map[string]Object{}
	attempted := map[string]bool{}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "cloudbuild.googleapis.com/BuildTrigger" {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(a.Name, "//cloudbuild.googleapis.com/"), "/")
		if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) {
			continue
		}
		req := buildRepositoryRequestFor(*a)
		if req.ref == "" {
			continue
		}
		rp := strings.Split(req.ref, "/")
		if rp[1] != projectID && "projects/"+rp[1] != number {
			out.record("viewer-build-references", 0, fmt.Errorf("out-of-project repository reference omitted"))
			continue
		}
		requestRef := req.ref
		if req.host == "sourcerepo.googleapis.com" {
			requestRef = "projects/" + projectID + strings.TrimPrefix(req.ref, "projects/"+rp[1])
		}
		key := req.host + "/" + req.version + "/" + requestRef
		if !attempted[key] {
			if len(attempted) >= 1000 {
				out.record("viewer-build-references", 0, fmt.Errorf("repository reference count exceeds bound"))
				break
			}
			attempted[key] = true
			raw, err := c.get(ctx, "https://"+key, url.Values{"fields": {"name," + req.field}})
			if err == nil && Str(raw["name"]) != req.ref && Str(raw["name"]) != requestRef {
				err = fmt.Errorf("repository metadata identity mismatch")
			}
			if err != nil {
				out.record("viewer-build-references:"+req.ref, 0, err)
				continue
			}
			// Only the selected field survives transient response processing.
			value, ok := raw[req.field].(string)
			if req.host == "sourcerepo.googleapis.com" {
				if _, exists := raw["mirrorConfig"]; !exists {
					out.record("viewer-build-references:"+req.ref, 0, nil)
					continue
				}
				value, ok = Get(raw, "mirrorConfig", "url").(string)
			}
			if !ok || value == "" {
				out.record("viewer-build-references:"+req.ref, 0, fmt.Errorf("missing provider identity metadata"))
				continue
			}
			cache[key] = Object{req.field: value}
		}
		raw := cache[key]
		if raw == nil {
			continue
		}
		id := Object{"kind": req.kind}
		if req.kind == "clone_uri" {
			id["uri"] = raw[req.field]
		} else {
			id["hostUri"] = raw[req.field]
			for _, field := range []string{"owner", "name", "projectKey", "repoSlug"} {
				id[field] = req.config[field]
			}
		}
		identity := RepositoryTrustIdentity(id)
		if identity == "" {
			out.record("viewer-build-references:"+req.ref, 0, fmt.Errorf("unsupported or malformed provider identity; no URL followed"))
			continue
		}
		a.Resource.Data["_gcpbusterResolvedBuildRepository"] = Object{"binding_digest": req.binding, "identity_digest": BuildTrustDigest(identity), "kind": req.kind, "basis": "selected_control_plane_reference_metadata"}
		if req.host == "sourcerepo.googleapis.com" {
			Obj(a.Resource.Data["_gcpbusterResolvedBuildRepository"])["resolution_source"] = "csr_mirror_metadata"
		}
		out.record("viewer-build-references:"+req.ref, 1, nil)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-build-references:limitations", Status: "notice", Error: "Observed in-project trigger references only; selected provider identity metadata is hashed, never followed. Visibility remains supplied evidence. No source, provider token, branch, webhook secret or connection credential is requested. Singular gitRepositoryLink references, SSH clone URIs, non-HTTPS/custom-port identities and malformed/denied metadata remain unknown."})
}
