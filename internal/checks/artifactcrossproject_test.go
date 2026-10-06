package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestArtifactCrossProjectExactDownloadAndIdentity(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//artifactregistry.googleapis.com/projects/repo-project/locations/us-central1/repositories/images", "resourceType": "artifactregistry.googleapis.com/Repository", "principal": "serviceAccount:worker@other-project.iam.gserviceaccount.com", "permissions": []any{"artifactregistry.repositories.downloadArtifacts"}, "condition": inventory.Object{"expression": "false"}})
	got := artifactCrossProjectAccess(a, time.Now())
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["service_account_project_id"] != "other-project" || !strings.Contains(got[0].Evidence["assessment"].(string), "same organization") {
		t.Fatal(got)
	}
	for _, principal := range []string{"allUsers", "user:person@other-project.example", "group:team@other-project.example", "serviceAccount:worker@repo-project.iam.gserviceaccount.com", "serviceAccount:service-123@gcp-sa-artifactregistry.iam.gserviceaccount.com", "serviceAccount:service-123@serverless-robot-prod.iam.gserviceaccount.com", "serviceAccount:service-123@container-engine-robot.iam.gserviceaccount.com", "deleted:serviceAccount:worker@other-project.iam.gserviceaccount.com"} {
		a.Resource.Data["principal"] = principal
		if len(artifactCrossProjectAccess(a, time.Now())) != 0 {
			t.Fatal("unproven cross-project principal", principal)
		}
	}
	a.Resource.Data["principal"] = "serviceAccount:worker@other-project.iam.gserviceaccount.com"
	a.Resource.Data["permissions"] = []any{"artifactregistry.repositories.get", "artifactregistry.repositories.list"}
	if len(artifactCrossProjectAccess(a, time.Now())) != 0 {
		t.Fatal("metadata permission is not download")
	}
	a.Resource.Data["permissions"] = []any{"artifactregistry.repositories.downloadArtifacts"}
	a.Resource.Data["resource"] = "//artifactregistry.googleapis.com/projects/123/locations/us-central1/repositories/images"
	if len(artifactCrossProjectAccess(a, time.Now())) != 0 {
		t.Fatal("numeric project alias is not a different project proof")
	}
}
