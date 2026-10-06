package report

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
)

func TestLegacyDBResourceNamesPreserveIdentityAndCapabilityRows(t *testing.T) {
	created, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	function := "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/api_v1_0_1"
	permissionSuffix := "/permission-analysis/0123456789abcdef01234567"
	fixture := []struct {
		title, module, resource, identity, name string
		detail                                  any
	}{
		{"function read", "iam_permission_risks", function + permissionSuffix, function, "api_v1_0_1", map[string]any{"asset_type": "gcpbuster.googleapis.com/PermissionGrant", "evidence": map[string]any{"resource": function, "capability": "read"}}},
		{"function list", "iam_permission_risks", function + permissionSuffix, function, "api_v1_0_1", map[string]any{"asset_type": "gcpbuster.googleapis.com/PermissionGrant", "evidence": map[string]any{"resource": function, "capability": "list"}}},
		{"function create", "iam_permission_risks", function + permissionSuffix, function, "api_v1_0_1", map[string]any{"asset_type": "gcpbuster.googleapis.com/PermissionGrant", "evidence": map[string]any{"resource": function, "capability": "create"}}},
		{"compute", "public_iam", "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/db-vm", "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/db-vm", "db-vm", nil},
		{"run", "public_iam", "//run.googleapis.com/projects/demo/locations/us-central1/services/api", "//run.googleapis.com/projects/demo/locations/us-central1/services/api", "api", nil},
		{"sql", "sql_hardening", "//cloudsql.googleapis.com/projects/demo/instances/database-prod", "//cloudsql.googleapis.com/projects/demo/instances/database-prod", "database-prod", nil},
		{"spanner", "public_iam", "//spanner.googleapis.com/projects/demo/instances/main/databases/app_db", "//spanner.googleapis.com/projects/demo/instances/main/databases/app_db", "app_db", nil},
		{"workspace", "workspace_groups", "workspace/groups/team@example.com", "workspace/groups/team@example.com", "team@example.com", nil},
		{"source capture", "configuration_plaintext", "//gcpbuster.googleapis.com/capturedConfiguration/opaque", "//run.googleapis.com/projects/demo/locations/us-central1/jobs/worker-job", "worker-job", map[string]any{"asset_type": "gcpbuster.googleapis.com/CapturedConfigurationValue", "evidence": map[string]any{"source": "//run.googleapis.com/projects/demo/locations/us-central1/jobs/worker-job", "value": "SYNTHETIC_FULL_PRIVATE_VALUE_" + strings.Repeat("x", 256<<10)}}},
		{"kingfisher source", "secrets_scan", "//gcpbuster.googleapis.com/secretScan/opaque", "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/startup-vm", "startup-vm", map[string]any{"evidence": map[string]any{"source": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/startup-vm", "match": "SYNTHETIC_PRIVATE_MATCH"}}},
		{"unknown synthetic", "configuration_plaintext", "//gcpbuster.googleapis.com/capturedConfiguration/deadbeef", "//gcpbuster.googleapis.com/capturedConfiguration/deadbeef", "", map[string]any{"evidence": map[string]any{"source": "not-a-resource", "value": "SYNTHETIC_PRIVATE_MATCH"}}},
	}
	for _, tc := range fixture {
		if err := created.Write(context.Background(), findings.Finding{ProjectID: "demo", Module: tc.module, Severity: findings.SevHigh, ResourceName: tc.resource, Title: tc.title, Detail: tc.detail}); err != nil {
			t.Fatal(err)
		}
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := engagement.OpenReadOnly(created.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	h := Handler(existing)
	w := serveReportRequest(h, "GET", "/api/findings")
	data := decodeServerJSON(t, w)
	rows := data["findings"].([]any)
	if len(rows) != len(fixture) || data["total"] != float64(len(fixture)) {
		t.Fatal("capability rows removed", data)
	}
	if len(w.Body.Bytes()) > 32<<10 || strings.Contains(w.Body.String(), "SYNTHETIC_") {
		t.Fatal("list loaded full secret detail", len(w.Body.Bytes()))
	}
	for i, tc := range fixture {
		row := rows[i].(map[string]any)
		if row["resource"] != tc.resource || row["resource_name"] != tc.name || row["resource_identity"] != tc.identity {
			t.Fatal(tc.title, row)
		}
		if _, exists := row["detail"]; exists {
			t.Fatal("list included secret detail", tc.title)
		}
	}
	detail := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings/1"))
	if detail["resource"] != function+permissionSuffix || detail["resource_identity"] != function || detail["resource_name"] != "api_v1_0_1" {
		t.Fatal(detail)
	}
	full := decodeServerJSON(t, serveReportRequest(h, "GET", "/api/findings/9"))
	if !strings.Contains(full["detail"].(string), "SYNTHETIC_FULL_PRIVATE_VALUE_") {
		t.Fatal("actual value no longer available")
	}
}

func TestStaticResourceColumnAndExportsEscapeNames(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	resource := "workspace/groups/<img src=x onerror=alert(1)>"
	if err := e.Write(context.Background(), findings.Finding{ProjectID: "demo", Module: "workspace_groups", Severity: findings.SevHigh, ResourceName: resource, Title: "Public archive", Detail: map[string]any{"evidence": map[string]any{"value": "SYNTHETIC_MANUAL_VALIDATION_VALUE"}}}); err != nil {
		t.Fatal(err)
	}
	if err := Export(e); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(e.Dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	if !strings.Contains(text, "<th>Resource</th>") || !strings.Contains(text, "class=\"resource-name\"") || !strings.Contains(text, "&lt;img src=x onerror=alert(1)&gt;") || strings.Contains(text, "<img src=x") {
		t.Fatal("missing or unsafe resource column", text)
	}
	if !strings.Contains(text, "SYNTHETIC_MANUAL_VALIDATION_VALUE") {
		t.Fatal("static report lost actual evidence")
	}
	jsonBytes, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(jsonBytes, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["resource_name"] != "<img src=x onerror=alert(1)>" || rows[0]["resource_identity"] != resource || rows[0]["resource"] != resource {
		t.Fatal(rows)
	}
	w := serveReportRequest(Handler(e), "GET", "/api/findings")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<img src=x") {
		t.Fatal(w.Code, w.Body.String())
	}
}
