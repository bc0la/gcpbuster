package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestCloudBuildTrustCorrelatorToFinding(t *testing.T) {
	a := inventory.NewAsset("//cloudbuild.googleapis.com/projects/123/locations/global/triggers/id", "cloudbuild.googleapis.com/BuildTrigger", inventory.Object{"disabled": false, "approvalConfig": inventory.Object{"approvalRequired": false}, "serviceAccount": "projects/demo/serviceAccounts/build@demo.iam.gserviceaccount.com", "github": inventory.Object{"owner": "org", "name": "repo", "pullRequest": inventory.Object{"commentControl": "COMMENTS_DISABLED"}}})
	snap := inventory.Snapshot{Assets: []inventory.Asset{a, inventory.NewAsset("//github.com/org/repo", inventory.GitHubRepositoryMetadataType, inventory.Object{"owner": "org", "name": "repo", "visibility": "public"}), inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"principal": "serviceAccount:build@demo.iam.gserviceaccount.com", "resource": "SENTINEL", "permissions": []any{"secretmanager.versions.access"}, "condition": inventory.Object{"expression": "SENTINEL"}})}}
	inventory.CorrelateBuildTrustContext(&snap)
	got := cloudBuildPRCommentControl(snap.Assets[0], time.Time{})
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatal(got)
	}
	evidence := buildTrustEvidence(snap.Assets[0])
	if evidence["repository_visibility"] != "public" || len(arr(evidence["high_impact_direct_grants"])) != 1 {
		t.Fatal(evidence)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	marker := obj(snap.Assets[0].Resource.Data["_gcpbusterBuildTrust"])
	marker["service_account"] = "foreign@elsewhere.iam.gserviceaccount.com"
	marker["repository_digest"] = strings.Repeat("a", 64)
	evidence = buildTrustEvidence(snap.Assets[0])
	if evidence["identity_status"] != "unknown" || evidence["repository_visibility"] != "unknown" {
		t.Fatal(evidence)
	}
}

func TestCloudBuildExtendedRepositoryVisibilityEvidence(t *testing.T) {
	prefix := "projects/123/locations/us-central1/"
	for _, tc := range []struct {
		family           string
		config, identity inventory.Object
	}{
		{"repositoryEventConfig", inventory.Object{"repository": prefix + "connections/c/repositories/r"}, inventory.Object{"kind": "clone_uri", "uri": "https://gitlab.example/org/repo.git"}},
		{"developerConnectEventConfig", inventory.Object{"gitRepositoryLink": prefix + "connections/c/gitRepositoryLinks/r"}, inventory.Object{"kind": "clone_uri", "uri": "https://github.com/org/repo.git"}},
		{"github", inventory.Object{"enterpriseConfigResourceName": prefix + "githubEnterpriseConfigs/e", "owner": "org", "name": "repo"}, inventory.Object{"kind": "github_enterprise", "hostUri": "https://github.example", "owner": "org", "name": "repo"}},
		{"bitbucketServerTriggerConfig", inventory.Object{"bitbucketServerConfigResource": prefix + "bitbucketServerConfigs/b", "projectKey": "KEY", "repoSlug": "repo"}, inventory.Object{"kind": "bitbucket_server", "hostUri": "https://bitbucket.example", "projectKey": "KEY", "repoSlug": "repo"}},
	} {
		tc.config["pullRequest"] = inventory.Object{"commentControl": "COMMENTS_DISABLED"}
		a := inventory.NewAsset("//cloudbuild.googleapis.com/"+prefix+"triggers/id", "cloudbuild.googleapis.com/BuildTrigger", inventory.Object{tc.family: tc.config})
		digest := inventory.BuildTrustDigest(inventory.RepositoryTrustIdentity(tc.identity))
		a.Resource.Data["_gcpbusterResolvedBuildRepository"] = inventory.Object{"binding_digest": inventory.BuildTriggerRepositoryBinding(a), "identity_digest": digest, "kind": tc.identity["kind"], "basis": "selected_control_plane_reference_metadata"}
		snap := inventory.Snapshot{Assets: []inventory.Asset{a, inventory.NewAsset("//gcpbuster.googleapis.com/repositoryTrust/"+digest, inventory.RepositoryTrustMetadataType, inventory.Object{"identity": tc.identity, "visibility": "public"})}}
		inventory.CorrelateBuildTrustContext(&snap)
		if len(cloudBuildPRCommentControl(snap.Assets[0], time.Time{})) != 1 || buildTrustEvidence(snap.Assets[0])["repository_visibility"] != "public" {
			t.Fatal(tc.family, snap)
		}
		obj(a.Resource.Data["_gcpbusterResolvedBuildRepository"])["binding_digest"] = strings.Repeat("0", 64)
		if buildTrustEvidence(a)["repository_visibility"] != "unknown" {
			t.Fatal("unbound marker", tc.family)
		}
	}
}
