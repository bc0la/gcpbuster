package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func buildTrustSnapshot() Snapshot {
	return Snapshot{Assets: []Asset{
		NewAsset("//cloudbuild.googleapis.com/projects/123/locations/global/triggers/id", "cloudbuild.googleapis.com/BuildTrigger", Object{"serviceAccount": "projects/demo/serviceAccounts/builder@demo.iam.gserviceaccount.com", "github": Object{"owner": "Example", "name": "Repo", "pullRequest": Object{"commentControl": "COMMENTS_DISABLED"}}}),
		NewAsset("//github.com/example/repo", GitHubRepositoryMetadataType, Object{"owner": "example", "name": "repo", "visibility": "public", "credential": "SENTINEL"}),
		NewAsset("grant", PermissionGrantType, Object{"principal": "serviceAccount:builder@demo.iam.gserviceaccount.com", "resource": "//secretmanager.googleapis.com/projects/123/secrets/SENTINEL", "permissions": []any{"secretmanager.versions.access", "SENTINEL"}, "condition": Object{"expression": "SENTINEL"}}),
	}}
}

func TestBuildTrustContextExplicitIdentityScopeAndRedaction(t *testing.T) {
	s := buildTrustSnapshot()
	CorrelateBuildTrustContext(&s)
	m := Obj(s.Assets[0].Resource.Data["_gcpbusterBuildTrust"])
	if m["repository_visibility"] != "public" || m["identity_status"] != "explicit_trigger_service_account" || len(List(m["high_impact_direct_grants"])) != 1 {
		t.Fatal(m)
	}
	row := Obj(List(m["high_impact_direct_grants"])[0])
	if row["condition_status"] != "supplied_unevaluated" || row["grant_resource_digest"] != BuildTrustDigest("//secretmanager.googleapis.com/projects/123/secrets/SENTINEL") {
		t.Fatal(row)
	}
	data, _ := json.Marshal(m)
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal(string(data))
	}
	s.Assets = s.Assets[:1]
	CorrelateBuildTrustContext(&s)
	m = Obj(s.Assets[0].Resource.Data["_gcpbusterBuildTrust"])
	if m["repository_visibility"] != "unknown" || len(List(m["high_impact_direct_grants"])) != 0 {
		t.Fatal("stale context", m)
	}
}

func TestBuildTrustContextUnknownAndConflictingEvidence(t *testing.T) {
	for _, mode := range []string{"missing_sa", "numeric_sa", "inline_sa", "different_principal", "repository_conflict", "enterprise", "enterprise_malformed", "trigger_conflict"} {
		s := buildTrustSnapshot()
		d := s.Assets[0].Resource.Data
		switch mode {
		case "missing_sa":
			delete(d, "serviceAccount")
		case "numeric_sa":
			d["serviceAccount"] = "projects/demo/serviceAccounts/12345"
		case "inline_sa":
			delete(d, "serviceAccount")
			d["build"] = Object{"serviceAccount": "projects/demo/serviceAccounts/builder@demo.iam.gserviceaccount.com"}
		case "different_principal":
			s.Assets[2].Resource.Data["principal"] = "serviceAccount:other@demo.iam.gserviceaccount.com"
		case "repository_conflict":
			s.Assets = append(s.Assets, NewAsset(s.Assets[1].Name, GitHubRepositoryMetadataType, Object{"owner": "example", "name": "repo", "visibility": "private"}))
		case "enterprise":
			Obj(d["github"])["enterpriseConfigResourceName"] = "projects/demo/locations/global/githubEnterpriseConfigs/private"
		case "enterprise_malformed":
			Obj(d["github"])["enterpriseConfigResourceName"] = true
		case "trigger_conflict":
			s.Assets = append(s.Assets, NewAsset(s.Assets[0].Name, s.Assets[0].Type, Object{}))
		}
		CorrelateBuildTrustContext(&s)
		m := Obj(d["_gcpbusterBuildTrust"])
		switch mode {
		case "missing_sa", "numeric_sa", "inline_sa", "trigger_conflict":
			if m["identity_status"] != "unknown" {
				t.Fatal(mode, m)
			}
		case "different_principal":
			if len(List(m["high_impact_direct_grants"])) != 0 {
				t.Fatal(mode, m)
			}
		default:
			if m["repository_visibility"] != "unknown" {
				t.Fatal(mode, m)
			}
		}
	}
}

func TestBuildTrustContextScopeKindsAndGrantBound(t *testing.T) {
	for resource, want := range map[string]string{
		"//cloudresourcemanager.googleapis.com/projects/123":                                      "project",
		"//iam.googleapis.com/projects/demo/serviceAccounts/account@demo.iam.gserviceaccount.com": "service_account",
		"//secretmanager.googleapis.com/projects/123/secrets/key":                                 "resource",
		"https://secret.invalid/value":                                                            "unknown",
	} {
		if got := buildTrustScope(resource); got != want {
			t.Fatal(resource, got)
		}
	}
	s := buildTrustSnapshot()
	grant := s.Assets[2]
	for i := 0; i < 110; i++ {
		s.Assets = append(s.Assets, grant)
	}
	CorrelateBuildTrustContext(&s)
	m := Obj(s.Assets[0].Resource.Data["_gcpbusterBuildTrust"])
	if len(List(m["high_impact_direct_grants"])) != 100 || m["grants_truncated"] != true {
		t.Fatal("grant bound not recorded")
	}
}
