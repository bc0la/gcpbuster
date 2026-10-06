package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type contentTransport func(*http.Request) (*http.Response, error)

func (f contentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// These historical collector-to-report tests exercise redaction and evidence
	// preservation, including collectors unavailable to the Viewer-only CLI.
	// This synthetic capability set is TEST ONLY, not Google's role definition
	// or evidence of Viewer compatibility. Separate policy/CLI tests prove that
	// the real three-role boundary rejects privileged collection requests.
	if r.Method == http.MethodGet && r.URL.Host == "iam.googleapis.com" {
		role := strings.TrimPrefix(r.URL.Path, "/v1/")
		if role == "roles/viewer" || role == "roles/resourcemanager.folderViewer" || role == "roles/resourcemanager.organizationViewer" {
			permissions := []string{
				"cloudasset.assets.listResource", "cloudasset.assets.listIamPolicy",
				"storage.objects.list", "storage.objects.get", "logging.logEntries.list",
				"iam.roles.get", "iam.serviceAccountKeys.list",
				"compute.backendServices.list",
				"resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy",
				"resourcemanager.folders.get", "resourcemanager.folders.getIamPolicy",
				"resourcemanager.organizations.get", "resourcemanager.organizations.getIamPolicy",
				"iap.web.getIamPolicy", "iap.webTypes.getIamPolicy", "iap.webServices.getIamPolicy",
				"iap.webServiceVersions.getIamPolicy", "iap.tunnel.getIamPolicy",
				"iap.tunnelZones.getIamPolicy", "iap.tunnelInstances.getIamPolicy",
				"iap.projects.getSettings", "iap.folders.getSettings", "iap.organizations.getSettings",
				"iap.web.getSettings", "iap.webTypes.getSettings", "iap.webServices.getSettings", "iap.webServiceVersions.getSettings",
				"appengine.applications.get", "appengine.services.list", "appengine.versions.list", "appengine.versions.get",
			}
			body, err := json.Marshal(map[string]any{"name": role, "includedPermissions": permissions})
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
		}
	}
	return f(r)
}

func TestCollectedContentPipelineNeverPersistsPayload(t *testing.T) {
	t.Setenv("CONTENT_TEST_TOKEN", "fixture-token")
	c := inventory.Client{TokenEnv: "CONTENT_TEST_TOKEN", HTTP: &http.Client{Transport: contentTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"kind":"storage#objects","items":[{"name":"config.env","generation":"7","size":"32"}]}`
		if r.URL.Host == "logging.googleapis.com" {
			body = `{"entries":[{"textPayload":"password=PIPELINE_SECRET_NOT_SAVED","logName":"projects/test/logs/app"}]}`
		} else if r.URL.Query().Get("alt") == "media" {
			body = "password=PIPELINE_SECRET_NOT_SAVED"
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	s := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//storage.googleapis.com/test-bucket", "storage.googleapis.com/Bucket", inventory.Object{"name": "test-bucket"})}}
	c.CollectStorage(context.Background(), &s, inventory.StorageOptions{ScanContent: true, MaxObjects: 10, MaxObjectBytes: 4096, MaxArchiveBytes: 8192, MaxArchiveEntries: 10})
	c.CollectLogs(context.Background(), &s, []string{"projects/test"}, inventory.LogOptions{MaxEntries: 10, MaxPages: 10, Since: time.Unix(1, 0), Until: time.Unix(2, 0)})
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "gcs_content_secrets" || ch.ID == "log_content_secrets" {
			selected = append(selected, ch)
		}
	}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = assess(context.Background(), cmd, e, s, selected, false)
	e.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"findings.json", "report.html", "engagement.db"} {
		b, err := os.ReadFile(filepath.Join(e.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("PIPELINE_SECRET_NOT_SAVED")) || bytes.Contains(b, []byte("fixture-token")) {
			t.Fatal("payload persisted in", name)
		}
		if name == "findings.json" && (!bytes.Contains(b, []byte("gcs_content_secrets")) || !bytes.Contains(b, []byte("log_content_secrets"))) {
			t.Fatal("missing content findings")
		}
	}
}

func TestOfflineEndToEndAndResume(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "engagement")
	run := func(extra ...string) error {
		cmd := rootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		// Legacy redacted evaluators/resume contract. New actual-value defaults
		// and the external scanner are tested in the secrets pipeline suite.
		args := []string{"scan", "--inventory", "../../examples/inventory.json", "--engagement", dir, "--exclude", "secrets_scan,configuration_plaintext"}
		cmd.SetArgs(append(args, extra...))
		return cmd.Execute()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "EXAMPLE_NOT_A_REAL_SECRET") || !strings.Contains(string(data), "[REDACTED]") {
		t.Fatal("redaction failed")
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"Best Practices", "Secrets Management", "IAM &amp; Access", "Public Exposure"} {
		if !strings.Contains(string(html), label) {
			t.Errorf("missing %s", label)
		}
	}
	if err := run("--resume"); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "findings.json"))
	if !bytes.Equal(data, again) {
		t.Fatal("resume duplicated/changed findings")
	}
	if err := run(); err == nil {
		t.Fatal("allowed accidental engagement reuse")
	}
}
func TestPartialCollectionProducesReportAndError(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	s := inventory.Snapshot{Coverage: []inventory.Coverage{{Source: "IAM_POLICY", Status: "failed", Error: "HTTP 403"}}}
	if err := assess(context.Background(), cmd, e, s, checks.All, false); err == nil {
		t.Fatal("partial collection reported success")
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "report.html")); err != nil {
		t.Fatal("no partial report", err)
	}
}

func TestOrgPolicySelectionValidationBeforeCollection(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--org-policy-checks", "--inventory", "../../examples/inventory.json"},
		{"scan", "--org-policy-checks", "--project", "test", "--modules", "public_iam"},
	} {
		cmd := rootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--org-policy-checks requires") {
			t.Fatal(err)
		}
	}
}

func TestOrgPolicyReportPipeline(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("policy/test", inventory.EffectiveOrgPolicyType, inventory.Object{
		"constraint": "iam.disableCrossProjectServiceAccountUsage", "scope": "projects/test", "effective": true,
		"spec": inventory.Object{"rules": []any{inventory.Object{"enforce": false}}},
	})}}
	var selected []checks.Check
	for _, c := range checks.All {
		if c.ID == "org_policy_guardrails" {
			selected = append(selected, c)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("org_policy_guardrails")) || checks.CategoryOf("org_policy_guardrails") != "best_practices" {
		t.Fatal("guardrail finding missing or miscategorized", string(b))
	}
}

func TestLifecycleCAIToReport(t *testing.T) {
	t.Setenv("LIFECYCLE_TEST_TOKEN", "fixture-token")
	c := inventory.Client{TokenEnv: "LIFECYCLE_TEST_TOKEN", HTTP: &http.Client{Transport: contentTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "cloudasset.googleapis.com" || r.Method != "GET" {
			t.Fatal("unexpected lifecycle request", r.URL)
		}
		body := `{"assets":[]}`
		if r.URL.Query().Get("contentType") == "RESOURCE" {
			types := r.URL.Query()["assetTypes"]
			for _, want := range []string{"secretmanager.googleapis.com/Secret", "secretmanager.googleapis.com/SecretVersion", "cloudkms.googleapis.com/CryptoKey", "cloudkms.googleapis.com/CryptoKeyVersion"} {
				found := false
				for _, typ := range types {
					found = found || typ == want
				}
				if !found {
					t.Fatal("metadata type not requested", want)
				}
			}
			body = `{"assets":[{"name":"//secretmanager.googleapis.com/projects/1/secrets/example/versions/1","assetType":"secretmanager.googleapis.com/SecretVersion","resource":{"data":{"state":"DISABLED","scheduledDestroyTime":"2099-01-01T00:00:00Z"}}},{"name":"//cloudkms.googleapis.com/projects/1/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1","assetType":"cloudkms.googleapis.com/CryptoKeyVersion","resource":{"data":{"state":"DESTROY_SCHEDULED","destroyTime":"2099-01-01T00:00:00Z"}}}]}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	s := c.Cloud(context.Background(), "projects/1")
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "secret_manager_lifecycle" || ch.ID == "kms_lifecycle" {
			selected = append(selected, ch)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"secret_manager_lifecycle", "kms_lifecycle"} {
		if !bytes.Contains(b, []byte(id)) {
			t.Fatal("missing report finding", id)
		}
	}
}

func TestGroupIAMCorrelationReportPipeline(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := inventory.Snapshot{Assets: []inventory.Asset{
		inventory.NewAsset("workspace/group", "workspace.googleapis.com/GroupSettings", inventory.Object{"email": "privileged@example.com", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN"}),
		{Name: "projects/test", IAM: inventory.Object{"bindings": []any{inventory.Object{"role": "roles/viewer", "members": []any{"group:privileged@example.com"}, "condition": inventory.Object{"expression": "resource.name.startsWith('projects/test')"}}}}},
	}}
	var selected []checks.Check
	for _, c := range checks.All {
		if c.ID == "workspace_group_iam_paths" {
			selected = append(selected, c)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"workspace_group_iam_paths", "ALL_IN_DOMAIN_CAN_JOIN", "resource.name.startsWith"} {
		if !bytes.Contains(b, []byte(value)) {
			t.Fatal("missing correlated evidence", value)
		}
	}
}

func TestWorkloadGrantOnlyModuleResolvesBindingPipeline(t *testing.T) {
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := inventory.Snapshot{Assets: []inventory.Asset{
		inventory.NewAsset("vm", "compute.googleapis.com/Instance", inventory.Object{"serviceAccounts": []any{inventory.Object{"email": "runner@p.iam.gserviceaccount.com", "scopes": []any{"read-only"}}}}),
		inventory.NewAsset("projects/p/roles/custom", "iam.googleapis.com/Role", inventory.Object{"name": "projects/p/roles/custom", "includedPermissions": []any{"iam.serviceAccountKeys.create"}}),
		{Name: "projects/p", IAM: inventory.Object{"bindings": []any{inventory.Object{"role": "projects/p/roles/custom", "members": []any{"serviceAccount:runner@p.iam.gserviceaccount.com"}}}}},
	}}
	var selected []checks.Check
	for _, c := range checks.All {
		if c.ID == "workload_identity_grants" {
			selected = append(selected, c)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"workload_identity_grants", "runner@p.iam.gserviceaccount.com", "read-only", "iam.serviceAccountKeys.create"} {
		if !bytes.Contains(b, []byte(value)) {
			t.Fatal("missing workload evidence", value)
		}
	}
}

func TestAncestorPolicyReportPipeline(t *testing.T) {
	t.Setenv("ANCESTOR_TEST_TOKEN", "fixture-token")
	c := inventory.Client{TokenEnv: "ANCESTOR_TEST_TOKEN", HTTP: &http.Client{Transport: contentTransport(func(r *http.Request) (*http.Response, error) {
		body := `{}`
		if r.Method == "GET" {
			if strings.Contains(r.URL.Path, "projects/") {
				body = `{"name":"projects/1","parent":"organizations/2"}`
			} else {
				body = `{"name":"organizations/2"}`
			}
		} else if strings.Contains(r.URL.Path, "organizations/") {
			body = `{"version":3,"bindings":[{"role":"roles/viewer","members":["allAuthenticatedUsers"],"condition":{"expression":"request.time < timestamp('2026-01-01T00:00:00Z')"}}]}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	s := inventory.Snapshot{}
	c.CollectAncestorIAM(context.Background(), &s, []string{"projects/1"})
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "public_iam" {
			selected = append(selected, ch)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, s, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"organizations/2", "allAuthenticatedUsers", "request.time"} {
		if !bytes.Contains(b, []byte(value)) {
			t.Fatal("lost ancestor evidence", value)
		}
	}
}

func TestInheritedAuditReportPipeline(t *testing.T) {
	project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/1", "cloudresourcemanager.googleapis.com/Project", inventory.Object{"parent": "organizations/2"})
	project.IAM = inventory.Object{}
	org := inventory.NewAsset("//cloudresourcemanager.googleapis.com/organizations/2", "cloudresourcemanager.googleapis.com/Organization", inventory.Object{"parent": ""})
	org.IAM = inventory.Object{"auditConfigs": []any{inventory.Object{"service": "allServices", "auditLogConfigs": []any{inventory.Object{"logType": "ADMIN_READ"}, inventory.Object{"logType": "DATA_READ", "exemptedMembers": []any{"user:except@example.com"}}, inventory.Object{"logType": "DATA_WRITE"}}}}}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var selected []checks.Check
	for _, ch := range checks.All {
		if ch.ID == "inherited_audit_logging" {
			selected = append(selected, ch)
		}
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := assess(context.Background(), cmd, e, inventory.Snapshot{Assets: []inventory.Asset{project, org}}, selected, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"inherited_audit_logging", "projects/1", "organizations/2", "user:except@example.com"} {
		if !bytes.Contains(b, []byte(value)) {
			t.Fatal("missing inherited audit evidence", value)
		}
	}
	if bytes.Contains(b, []byte("lack a complete all-services")) {
		t.Fatal("ignored parent baseline")
	}
}
func TestMergeResourceAndIAM(t *testing.T) {
	a := inventory.NewAsset("same", "storage.googleapis.com/Bucket", inventory.Object{"name": "same"})
	p := inventory.Asset{Name: a.Name, Type: a.Type, IAM: inventory.Object{"bindings": []any{}}}
	got := mergeAssets([]inventory.Asset{a, p, a})
	if len(got) != 1 || got[0].IAM == nil || got[0].Resource.Data == nil {
		t.Fatal(got)
	}
}

func TestMergeDirectPolicyWinsOverSearchInEitherOrder(t *testing.T) {
	direct := inventory.Asset{Name: "//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/r/cryptoKeys/k", Type: "cloudkms.googleapis.com/CryptoKey", IAM: inventory.Object{"version": 3, "etag": "direct", "bindings": []any{}}}
	search := direct
	search.IAM = inventory.Object{"_gcpbusterBindingsOnly": true, "etag": "stale", "bindings": []any{inventory.Object{"role": "roles/owner", "members": []any{"allUsers"}}}}
	for _, rows := range [][]inventory.Asset{{direct, search}, {search, direct}, {direct, search, search}} {
		got := mergeAssets(rows)
		if len(got) != 1 || inventory.Str(got[0].IAM["etag"]) != "direct" || inventory.Bool(got[0].IAM["_gcpbusterBindingsOnly"]) {
			t.Fatal(got)
		}
	}
}

func TestScoutExplicitScope(t *testing.T) {
	for _, scope := range []string{"projects/demo", "folders/123", "organizations/456"} {
		args, err := scoutArgs(scope, "/tmp/report", "/tmp/key file.json")
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, "|")
		if !strings.Contains(joined, "--service-account|/tmp/key file.json") || strings.Contains(joined, "--all-projects") {
			t.Fatal(args)
		}
	}
	if _, err := scoutArgs("", "", ""); err == nil {
		t.Fatal("allowed implicit scope")
	}
}

func TestResumeAllowsAdditionalPermissionModules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "engagement")
	for i, modules := range []string{"public_iam", "iam_permission_risks,public_permission_capabilities"} {
		cmd := rootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		args := []string{"scan", "--inventory", "../../examples/inventory.json", "--engagement", dir, "--modules", modules}
		if i > 0 {
			args = append(args, "--resume")
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"public_iam", "iam_permission_risks", "public_permission_capabilities"} {
		if !strings.Contains(string(data), module) {
			t.Fatalf("missing additional module %s", module)
		}
	}
}
