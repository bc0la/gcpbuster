package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func buildReferenceTrigger(family string, config Object) Asset {
	config["pullRequest"] = Object{"commentControl": "COMMENTS_DISABLED"}
	return NewAsset("//cloudbuild.googleapis.com/projects/123/locations/us-central1/triggers/"+family, "cloudbuild.googleapis.com/BuildTrigger", Object{family: config})
}

func TestViewerBuildRepositoryClearsStaleMarkersAtRequestBound(t *testing.T) {
	out := Snapshot{}
	for i := 0; i < 1002; i++ {
		a := buildReferenceTrigger("repositoryEventConfig", Object{"repository": fmt.Sprintf("projects/demo/locations/us-central1/connections/c/repositories/r%d", i)})
		a.Resource.Data["_gcpbusterResolvedBuildRepository"] = Object{"stale": true}
		out.Assets = append(out.Assets, a)
	}
	foreign := buildReferenceTrigger("repositoryEventConfig", Object{})
	foreign.Name = "//cloudbuild.googleapis.com/projects/foreign/locations/us-central1/triggers/t"
	foreign.Resource.Data["_gcpbusterResolvedBuildRepository"] = Object{"other_project": true}
	out.Assets = append(out.Assets, foreign)
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return response(403, `{"error":{"message":"denied"}}`), nil
	})
	c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
	if calls != 1000 {
		t.Fatal(calls)
	}
	for _, a := range out.Assets[:1002] {
		if a.Resource.Data["_gcpbusterResolvedBuildRepository"] != nil {
			t.Fatal("stale marker survived bound")
		}
	}
	if foreign.Resource.Data["_gcpbusterResolvedBuildRepository"] == nil {
		t.Fatal("other project was erased")
	}
}

func TestViewerBuildRepositoryReferencesFamiliesAndRedaction(t *testing.T) {
	prefix := "projects/demo/locations/us-central1/"
	fixtures := []struct {
		family            string
		config, identity  Object
		ref, field, value string
	}{
		{"repositoryEventConfig", Object{"repository": prefix + "connections/c/repositories/r"}, Object{"kind": "clone_uri", "uri": "https://github.com/org/repo.git"}, prefix + "connections/c/repositories/r", "remoteUri", "https://github.com/org/repo.git"},
		{"developerConnectEventConfig", Object{"gitRepositoryLink": prefix + "connections/c/gitRepositoryLinks/r"}, Object{"kind": "clone_uri", "uri": "https://gitlab.example/group/repo.git"}, prefix + "connections/c/gitRepositoryLinks/r", "cloneUri", "https://gitlab.example/group/repo.git"},
		{"github", Object{"enterpriseConfigResourceName": prefix + "githubEnterpriseConfigs/e", "owner": "org", "name": "repo"}, Object{"kind": "github_enterprise", "hostUri": "https://github.example", "owner": "org", "name": "repo"}, prefix + "githubEnterpriseConfigs/e", "hostUrl", "https://github.example"},
		{"bitbucketServerTriggerConfig", Object{"bitbucketServerConfigResource": prefix + "bitbucketServerConfigs/b", "projectKey": "KEY", "repoSlug": "repo"}, Object{"kind": "bitbucket_server", "hostUri": "https://bitbucket.example/context", "projectKey": "KEY", "repoSlug": "repo"}, prefix + "bitbucketServerConfigs/b", "hostUri", "https://bitbucket.example/context"},
	}
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || (r.URL.Host != "cloudbuild.googleapis.com" && r.URL.Host != "developerconnect.googleapis.com") {
			t.Fatal(r.URL)
		}
		for _, f := range fixtures {
			if strings.HasSuffix(r.URL.Path, "/"+f.ref) {
				if r.URL.Query().Get("fields") != "name,"+f.field || len(r.URL.Query()) != 1 {
					t.Fatal(r.URL)
				}
				raw, _ := json.Marshal(Object{"name": f.ref, f.field: f.value, "secret": "SENTINEL", "apiKey": "SENTINEL", "webhookKey": "SENTINEL"})
				return response(200, string(raw)), nil
			}
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	out := Snapshot{}
	for _, f := range fixtures {
		out.Assets = append(out.Assets, buildReferenceTrigger(f.family, f.config))
	}
	c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
	if calls != 4 {
		t.Fatal(calls)
	}
	for i, f := range fixtures {
		digest := BuildTrustDigest(RepositoryTrustIdentity(f.identity))
		if BuildTriggerRepositoryIdentityDigest(out.Assets[i]) != digest {
			t.Fatal(f.family, out.Assets[i])
		}
		raw, _ := json.Marshal(out.Assets[i].Resource.Data["_gcpbusterResolvedBuildRepository"])
		if strings.Contains(string(raw), "SENTINEL") || strings.Contains(string(raw), "https:") {
			t.Fatal(string(raw))
		}
		out.Assets = append(out.Assets, NewAsset("//gcpbuster.googleapis.com/repositoryTrust/"+digest, RepositoryTrustMetadataType, Object{"identity": f.identity, "visibility": "public"}))
	}
	CorrelateBuildTrustContext(&out)
	for i := range fixtures {
		if Get(out.Assets[i].Resource.Data, "_gcpbusterBuildTrust", "repository_visibility") != "public" {
			t.Fatal(out.Assets[i])
		}
	}
	// Reference changes cannot reuse a previous successful observation.
	Obj(out.Assets[0].Resource.Data["repositoryEventConfig"])["repository"] = prefix + "connections/c/repositories/other"
	if BuildTriggerRepositoryIdentityDigest(out.Assets[0]) != "" {
		t.Fatal("stale binding reused")
	}
}

func TestViewerBuildRepositoryReferencesDenialScopeAndURLUnknown(t *testing.T) {
	base := "projects/demo/locations/us-central1/connections/c/repositories/"
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/denied") {
			return response(403, `{"error":{"message":"denied"}}`), nil
		}
		raw, _ := json.Marshal(Object{"name": strings.TrimPrefix(r.URL.Path, "/v2/"), "remoteUri": "https://user:SENTINEL@github.com/org/repo"})
		return response(200, string(raw)), nil
	})
	out := Snapshot{Assets: []Asset{buildReferenceTrigger("repositoryEventConfig", Object{"repository": base + "denied"}), buildReferenceTrigger("repositoryEventConfig", Object{"repository": base + "secret"}), buildReferenceTrigger("repositoryEventConfig", Object{"repository": "projects/foreign/locations/us-central1/connections/c/repositories/r"})}}
	c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
	if calls != 2 || !hasCoverage(out, "failed") {
		t.Fatal(calls, out.Coverage)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	for _, a := range out.Assets {
		if BuildTriggerRepositoryIdentityDigest(a) != "" {
			t.Fatal("invalid metadata matched")
		}
	}
	delete(c.viewerPolicy.permissions, "cloudbuild.repositories.get")
	calls = 0
	c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
	if calls != 0 {
		t.Fatal("role gate bypass")
	}
}

func TestViewerBuildRepositoryGuardAndIdentityBounds(t *testing.T) {
	endpoint := "https://cloudbuild.googleapis.com/v2/projects/demo/locations/us-central1/connections/c/repositories/r"
	perms, err := viewerRequestPermissions("GET", endpoint, url.Values{"fields": {"name,remoteUri"}})
	if err != nil || len(perms) != 1 || perms[0] != "cloudbuild.repositories.get" {
		t.Fatal(perms, err)
	}
	for _, q := range []url.Values{nil, {"fields": {"*"}}, {"fields": {"name,remoteUri"}, "alt": {"media"}}, {"fields": {"name,remoteUri", "name"}}} {
		if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
			t.Fatal(q)
		}
	}
	for _, suffix := range []string{":accessReadToken", ":accessReadWriteToken", ":fetchGitRefs"} {
		if _, err := viewerRequestPermissions("POST", endpoint+suffix, nil); err == nil {
			t.Fatal(suffix)
		}
	}
	for _, uri := range []string{"http://github.com/o/r", "https://user:pass@github.com/o/r", "https://github.com/o/r?token=secret", "https://github.com:443/o/r", "https://github.com/o/%2e%2e/r", "git@github.com:o/r.git", "https://github.com/o//r"} {
		if RepositoryTrustIdentity(Object{"kind": "clone_uri", "uri": uri}) != "" {
			t.Fatal(uri)
		}
	}
	plain := RepositoryTrustIdentity(Object{"kind": "clone_uri", "uri": "https://arbitrary.example/repo"})
	trailing := RepositoryTrustIdentity(Object{"kind": "clone_uri", "uri": "https://arbitrary.example/repo/"})
	if plain == "" || plain == trailing {
		t.Fatal("opaque clone path conflation")
	}
}
