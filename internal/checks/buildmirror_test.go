package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestCloudBuildMirroredSourceExplicitBoundContext(t *testing.T) {
	a := inventory.NewAsset("//cloudbuild.googleapis.com/projects/123/locations/global/triggers/t", "cloudbuild.googleapis.com/BuildTrigger", inventory.Object{"triggerTemplate": inventory.Object{"repoName": "repo", "branchName": "SENTINEL"}, "disabled": false, "approvalConfig": inventory.Object{"approvalRequired": true}})
	a.Resource.Data["_gcpbusterResolvedBuildRepository"] = inventory.Object{"binding_digest": inventory.BuildTriggerRepositoryBinding(a), "identity_digest": strings.Repeat("a", 64), "kind": "clone_uri", "basis": "selected_control_plane_reference_metadata", "resolution_source": "csr_mirror_metadata"}
	got := cloudBuildMirroredSource(a, time.Time{})
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["revision_selector"] != "branchName" {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	for _, mode := range []string{"disabled", "mixed_revision", "malformed_enabled", "stale_ref", "wrong_marker"} {
		b := inventory.NewAsset(a.Name, a.Type, inventory.Object{})
		for k, v := range a.Resource.Data {
			b.Resource.Data[k] = v
		}
		b.Resource.Data["triggerTemplate"] = inventory.Object{"repoName": "repo", "branchName": "x"}
		switch mode {
		case "disabled":
			b.Resource.Data["disabled"] = true
		case "mixed_revision":
			obj(b.Resource.Data["triggerTemplate"])["tagName"] = "v"
		case "malformed_enabled":
			b.Resource.Data["disabled"] = "false"
		case "stale_ref":
			obj(b.Resource.Data["triggerTemplate"])["repoName"] = "other"
		case "wrong_marker":
			b.Resource.Data["_gcpbusterResolvedBuildRepository"] = nil
		}
		if got := cloudBuildMirroredSource(b, time.Time{}); len(got) != 0 {
			t.Fatal(mode, got)
		}
	}
}
