package report

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestResourceMetadataNamesAndExactSyntheticSuffix(t *testing.T) {
	for _, tc := range []struct{ identity, name string }{
		{"//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/api_v1", "api_v1"},
		{"//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/myAPI-public", "myAPI-public"},
		{"//storage.googleapis.com/customer-bucket", "customer-bucket"},
		{"//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/web-1", "web-1"},
		{"//run.googleapis.com/projects/demo/locations/us-central1/services/edge", "edge"},
		{"//sqladmin.googleapis.com/projects/demo/instances/database", "database"},
		{"//iam.googleapis.com/projects/demo/serviceAccounts/viewer@demo.iam.gserviceaccount.com", "viewer@demo.iam.gserviceaccount.com"},
		{"workspace/groups/engineering", "engineering"},
		{"projects/demo", "demo"},
	} {
		name, identity := resourceMetadata(tc.identity+"/permission-analysis/abcdefabcdefabcdefabcdef", "")
		if name != tc.name || identity != tc.identity {
			t.Fatalf("metadata wrong: %s %s", name, identity)
		}
	}
	name, identity := resourceMetadata("//gcpbuster.googleapis.com/secretFindings/opaque", "")
	if name != "" || identity != "//gcpbuster.googleapis.com/secretFindings/opaque" {
		t.Fatal("synthetic hash guessed")
	}
	name, _ = resourceMetadata("//storage.googleapis.com/bucket/permission-analysis/not-a-hash", "")
	if name != "not-a-hash" {
		t.Fatal("genuine path stripped")
	}
}

func TestResourceMetadataLegacyDBListDetailReadAndExport(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	resource := "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/api_v1"
	wrapped := resource + "/permission-analysis/abcdefabcdefabcdefabcdef"
	for _, f := range []findings.Finding{
		{ProjectID: "demo", Module: "public_iam", Severity: findings.SevHigh, ResourceName: wrapped, Detail: map[string]any{"asset_type": "gcpbuster.googleapis.com/PermissionGrant", "evidence": map[string]string{"resource": resource, "match": "SHOULD_NOT_BE_RESOURCE"}}},
		{ProjectID: "demo", Module: "secrets_scan", Severity: findings.SevHigh, ResourceName: "//gcpbuster.googleapis.com/secretFindings/opaque", Detail: map[string]any{"evidence": map[string]string{"source": resource, "match": strings.Repeat("SHOULD_NOT_BE_RESOURCE", 14000)}}},
	} {
		if err := e.Write(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	APIHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/findings", nil))
	var list struct{ Findings []BriefRow }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Findings) != 2 {
		t.Fatalf("list metadata failed: %d %s", w.Code, w.Body.String())
	}
	for _, row := range list.Findings {
		if row.ResourceName != "api_v1" || row.ResourceIdentity != resource {
			t.Fatalf("list wrong %+v", row)
		}
	}
	if w.Body.Len() > 8192 || strings.Contains(w.Body.String(), "SHOULD_NOT_BE_RESOURCE") {
		t.Fatal("list loaded full secret detail")
	}
	w = httptest.NewRecorder()
	APIHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/findings/1", nil))
	var detail QueryRow
	if json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.ResourceName != "api_v1" || detail.Resource != wrapped {
		t.Fatal("detail metadata/original resource lost")
	}
	w = httptest.NewRecorder()
	APIHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/findings/2", nil))
	if json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.ResourceName != "api_v1" || detail.ResourceIdentity != resource || len(detail.Detail) <= 256<<10 {
		t.Fatal("large synthetic detail lost source metadata")
	}
	_, rows, err := Read(e.DB())
	if err != nil || rows[0].ResourceName != "api_v1" || rows[0].ResourceIdentity != resource {
		t.Fatal("static metadata differs")
	}
	w = httptest.NewRecorder()
	ExportHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/export/json", nil))
	var exported []exportRow
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &exported) != nil || exported[0].ResourceName != "api_v1" || exported[0].ResourceIdentity != resource || exported[0].Resource != wrapped {
		t.Fatal("JSON export metadata differs")
	}
	if exported[1].ResourceName != "api_v1" || exported[1].ResourceIdentity != resource || len(exported[1].Detail) <= 256<<10 {
		t.Fatal("large exported synthetic value lost resource metadata")
	}
}

func TestResourceMetadataReviewedSyntheticFamilies(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	project := "//cloudresourcemanager.googleapis.com/projects/demo"
	cases := []struct{ typ, resource, key, identity, name string }{
		{"ArtifactUpstreams", "//artifactregistry.googleapis.com/projects/demo/locations/us/repositories/repo/upstream-analysis", "resource", "//artifactregistry.googleapis.com/projects/demo/locations/us/repositories/repo", "repo"},
		{"InheritedAuditConfig", project + "/inherited-audit-config", "resource", project, "demo"},
		{"WorkloadIdentityGrant", "//run.googleapis.com/projects/demo/locations/us/services/api/workload-grants/0/1", "workload", "//run.googleapis.com/projects/demo/locations/us/services/api", "api"},
		{"GroupIAMBinding", project + "/group-iam/0/1", "bound_resource", project, "engineering@example.test"},
		{"ManagedRotationPrerequisite", "//gcpbuster.googleapis.com/managed-rotation-prerequisite/opaque", "secret", "//secretmanager.googleapis.com/projects/demo/locations/us/secrets/database", "database"},
		{"GroupIAMBinding", project + "/group-iam/0/2", "bound_resource", project, "operations@example.test"},
	}
	for _, tc := range cases {
		evidence := map[string]string{tc.key: tc.identity, "value": "NOT_RESOURCE_SECRET"}
		if tc.typ == "GroupIAMBinding" {
			evidence["group"] = tc.name
		}
		detail := map[string]any{"asset_type": "gcpbuster.googleapis.com/" + tc.typ, "evidence": evidence}
		if err := e.Write(context.Background(), findings.Finding{Module: "review", Severity: findings.SevHigh, ResourceName: tc.resource, Detail: detail}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	APIHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/findings", nil))
	var list struct{ Findings []BriefRow }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Findings) != len(cases) {
		t.Fatalf("list failed %d %s", w.Code, w.Body.String())
	}
	_, static, err := Read(e.DB())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	ExportHandler(e.DB()).ServeHTTP(w, httptest.NewRequest("GET", "/api/export/json", nil))
	var exported []exportRow
	if json.Unmarshal(w.Body.Bytes(), &exported) != nil {
		t.Fatal("export failed")
	}
	for i, tc := range cases {
		identity := tc.identity
		if tc.typ == "GroupIAMBinding" {
			identity = "workspace/groups/" + tc.name
		}
		if list.Findings[i].ResourceName != tc.name || list.Findings[i].ResourceIdentity != identity || static[i].ResourceName != tc.name || exported[i].ResourceName != tc.name {
			t.Fatalf("%s metadata wrong: %+v", tc.typ, list.Findings[i])
		}
	}
	if candidate := groupResourceCandidate("Team <engineering@example.test>", project); candidate != project {
		t.Fatal("display-name email accepted")
	}
	if candidate := groupResourceCandidate("credential-not-email", project); candidate != project {
		t.Fatal("secret-like group string accepted")
	}
}
