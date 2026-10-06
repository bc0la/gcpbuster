package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestViewerCSRMirrorScopeDefaultsAndVisibility(t *testing.T) {
	a := buildReferenceTrigger("triggerTemplate", Object{"repoName": "nested/repo", "branchName": "PRIVATE_REGEX"})
	// Source branch triggers do not have a pull-request filter.
	delete(Obj(a.Resource.Data["triggerTemplate"]), "pullRequest")
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "sourcerepo.googleapis.com" || r.URL.Path != "/v1/projects/demo/repos/nested/repo" || r.URL.Query().Get("fields") != viewerCSRMirrorFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"name":"projects/demo/repos/nested/repo","mirrorConfig":{"url":"https://github.com/org/repo.git","webhookId":"SENTINEL","deployKeyId":"SENTINEL"},"url":"SENTINEL","pubsubConfigs":{"SENTINEL":{}}}`), nil
	})
	out := Snapshot{Assets: []Asset{a}}
	c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
	if calls != 1 || !BuildTriggerCSRMirrorConfigured(out.Assets[0]) {
		t.Fatal(calls, out)
	}
	marker := out.Assets[0].Resource.Data["_gcpbusterResolvedBuildRepository"]
	raw, _ := json.Marshal(marker)
	if strings.Contains(string(raw), "SENTINEL") || strings.Contains(string(raw), "https") {
		t.Fatal(string(raw))
	}
	out.Assets = append(out.Assets, NewAsset("//github.com/org/repo", GitHubRepositoryMetadataType, Object{"owner": "org", "name": "repo", "visibility": "public"}))
	CorrelateBuildTrustContext(&out)
	if Get(out.Assets[0].Resource.Data, "_gcpbusterBuildTrust", "repository_visibility") != "public" {
		t.Fatal(out)
	}
	Obj(a.Resource.Data["triggerTemplate"])["repoName"] = "different"
	if BuildTriggerCSRMirrorConfigured(a) {
		t.Fatal("stale mirror reference")
	}
}

func TestViewerCSRMirrorDenialAndMalformedUnknown(t *testing.T) {
	for _, mode := range []string{"absent", "foreign_response", "credentials", "denied", "foreign_project", "malformed_project", "traversal", "missing_role"} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			switch mode {
			case "absent":
				return response(200, `{"name":"projects/demo/repos/repo"}`), nil
			case "foreign_response":
				return response(200, `{"name":"projects/other/repos/repo","mirrorConfig":{"url":"https://github.com/o/r"}}`), nil
			case "credentials":
				return response(200, `{"name":"projects/demo/repos/repo","mirrorConfig":{"url":"https://user:SENTINEL@github.com/o/r"}}`), nil
			default:
				return response(403, `{"error":{"message":"denied"}}`), nil
			}
		})
		a := buildReferenceTrigger("triggerTemplate", Object{"repoName": "repo", "projectId": "demo", "tagName": "v.*"})
		d := Obj(a.Resource.Data["triggerTemplate"])
		delete(d, "pullRequest")
		switch mode {
		case "foreign_project":
			d["projectId"] = "other"
		case "malformed_project":
			d["projectId"] = false
		case "traversal":
			d["repoName"] = "repo/.."
		case "missing_role":
			delete(c.viewerPolicy.permissions, "source.repos.get")
		}
		out := Snapshot{Assets: []Asset{a}}
		c.CollectViewerBuildRepositoryReferences(context.Background(), &out, "demo", "projects/123")
		if BuildTriggerCSRMirrorConfigured(a) {
			t.Fatal(mode)
		}
		if (mode == "foreign_project" || mode == "malformed_project" || mode == "traversal" || mode == "missing_role") && calls != 0 {
			t.Fatal(mode, calls)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "SENTINEL") {
			t.Fatal(mode, string(raw))
		}
	}
	endpoint := "https://sourcerepo.googleapis.com/v1/projects/demo/repos/nested/repo"
	perms, err := viewerRequestPermissions("GET", endpoint, url.Values{"fields": {viewerCSRMirrorFields}})
	if err != nil || len(perms) != 1 || perms[0] != "source.repos.get" {
		t.Fatal(perms, err)
	}
	for _, suffix := range []string{"/..", ":sync", "/git-upload-pack", "?alt=media"} {
		if _, err := viewerRequestPermissions("GET", endpoint+suffix, nil); err == nil {
			t.Fatal(suffix)
		}
	}
}
