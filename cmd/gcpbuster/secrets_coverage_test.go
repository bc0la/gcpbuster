package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/kingfisher"
)

type coverageTransport func(*http.Request) (*http.Response, error)

func (f coverageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These fixtures exercise collector-to-report plumbing against synthetic HTTP
// responses, not a live tenant or provider credential-validation service.
func TestSecretsNewCollectorsActualAndRedactedArtifacts(t *testing.T) {
	const value = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, redact := range []bool{false, true} {
		t.Run(fmt.Sprintf("redact=%v", redact), func(t *testing.T) {
			t.Setenv("GCPBUSTER_COVERAGE_TOKEN", "synthetic-token-never-sent-to-network")
			calls := 0
			roles := 0
			transport := coverageTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				body := ""
				if r.Method != "GET" {
					t.Fatal("mutation or exchange")
				}
				if strings.HasPrefix(r.URL.Path, "/api/") && (r.URL.Host != "etl-demo-dot-usc1.datafusion.googleusercontent.com" || r.URL.RawQuery != "") {
					t.Fatal("escaped or unbound CDAP metadata request", r.URL)
				}
				if r.URL.Host == "iam.googleapis.com" {
					roles++
					b, _ := json.Marshal(map[string]any{"name": strings.TrimPrefix(r.URL.Path, "/v1/"), "includedPermissions": []string{"parametermanager.locations.list", "parametermanager.templates.list", "parametermanager.templateVersions.list", "parametermanager.templateVersions.get", "parametermanager.parameters.list", "parametermanager.parameterVersions.list", "parametermanager.parameterVersions.get", "deploymentmanager.deployments.list", "deploymentmanager.manifests.list", "deploymentmanager.manifests.get", "notebooks.instances.list", "notebooks.instances.get", "datafusion.locations.list", "datafusion.instances.list", "datafusion.instances.get", "datafusion.namespaces.list", "datafusion.namespaces.get", "datafusion.pipelines.list", "datafusion.pipelines.get", "datafusion.pipelineConnections.list", "firebaseapphosting.locations.list", "firebaseapphosting.backends.list", "firebaseapphosting.builds.list", "clouddeploy.locations.list", "clouddeploy.deliveryPipelines.list", "clouddeploy.targets.list", "clouddeploy.releases.list"}})
					body = string(b)
				} else {
					switch r.URL.Path {
					case "/v1/projects/123/locations":
						body = `{}`
						if r.URL.Host != "parametermanager.googleapis.com" {
							body = `{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`
						}
					case "/v1/projects/123/locations/us-central1/instances":
						body = `{"instances":[{"name":"projects/demo/locations/us-central1/instances/f","options":{"PASSWORD":"` + value + `"}}]}`
					case "/v1/projects/123/locations/us-central1/instances/f":
						if r.URL.Host != "datafusion.googleapis.com" || r.URL.Query().Get("fields") != "name,apiEndpoint" {
							t.Fatal("unexpected endpoint binding read")
						}
						body = `{"name":"projects/demo/locations/us-central1/instances/f","apiEndpoint":"https://etl-demo-dot-usc1.datafusion.googleusercontent.com/api"}`
					case "/api/v3/namespaces":
						body = `[{"name":"chosen","config":{"secret":"DO_NOT_CAPTURE"}}]`
					case "/api/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/chosen/connections":
						body = `[{"connectionId":"mysql","plugin":{"properties":{"PASSWORD":"` + value + `"}},"secureKey":"DO_NOT_CAPTURE"}]`
					case "/api/v3/namespaces/chosen/apps":
						body = `[{"name":"etl","artifact":{"name":"cdap-data-pipeline"}},{"name":"unrelated","artifact":{"name":"other"}}]`
					case "/api/v3/namespaces/chosen/apps/etl":
						payload, _ := json.Marshal(map[string]any{"name": "etl", "configuration": `{"properties":{"PASSWORD":"` + value + `"},"stages":[{"plugin":{"properties":{"PASSWORD":"` + value + `"}}}],"postActions":[{"plugin":{"properties":{"PASSWORD":"` + value + `"}}}],"outputs":"DO_NOT_CAPTURE"}`})
						body = string(payload)
					case "/v1/projects/123/locations/us-central1/backends":
						body = `{"backends":[{"name":"projects/demo/locations/us-central1/backends/b"}]}`
					case "/v1/projects/123/locations/us-central1/backends/b/builds":
						body = `{"builds":[{"name":"projects/demo/locations/us-central1/backends/b/builds/x","config":{"effectiveEnv":[{"variable":"PASSWORD","value":"` + value + `"}]}}]}`
					case "/v1/projects/123/locations/us-central1/deliveryPipelines":
						body = `{"deliveryPipelines":[{"name":"projects/demo/locations/us-central1/deliveryPipelines/p","serialPipeline":{"stages":[{"deployParameters":[{"values":{"PASSWORD":"` + value + `"}}]}]}}]}`
					case "/v1/projects/123/locations/us-central1/deliveryPipelines/p/releases":
						body = `{"releases":[{"name":"projects/demo/locations/us-central1/deliveryPipelines/p/releases/r","deployParameters":{"PASSWORD":"` + value + `"}}]}`
					case "/v1/projects/123/locations/us-central1/targets":
						body = `{"targets":[{"name":"projects/demo/locations/us-central1/targets/t","deployParameters":{"PASSWORD":"` + value + `"}}]}`
					case "/v1/projects/123/locations/global/parameters":
						body = `{"parameters":[{"name":"projects/123/locations/global/parameters/p"}]}`
					case "/v1/projects/123/locations/global/templates":
						body = `{"templates":[{"name":"projects/123/locations/global/templates/password_blueprint"}]}`
					case "/v1/projects/123/locations/global/templates/password_blueprint/versions":
						body = `{"templateVersions":[{"name":"projects/123/locations/global/templates/password_blueprint/versions/v"}]}`
					case "/v1/projects/123/locations/global/templates/password_blueprint/versions/v":
						if r.URL.Query().Has("view") {
							t.Fatal("template rendering/view selector invented")
						}
						body = `{"name":"projects/123/locations/global/templates/password_blueprint/versions/v","payload":{"data":"` + base64.StdEncoding.EncodeToString([]byte("password="+value)) + `"}}`
					case "/v1/projects/123/locations/global/parameters/p/versions":
						body = `{"parameterVersions":[{"name":"projects/123/locations/global/parameters/p/versions/v"}]}`
					case "/v1/projects/123/locations/global/parameters/p/versions/v":
						body = `{"name":"projects/123/locations/global/parameters/p/versions/v","payload":{"data":"` + base64.StdEncoding.EncodeToString([]byte("password="+value)) + `"}}`
					case "/deploymentmanager/v2/projects/123/global/deployments":
						body = `{"deployments":[{"name":"d"}]}`
					case "/deploymentmanager/v2/projects/123/global/deployments/d/manifests":
						body = `{"manifests":[{"name":"m"}]}`
					case "/deploymentmanager/v2/projects/123/global/deployments/d/manifests/m":
						body = `{"name":"m","config":{"content":"password=` + value + `"}}`
					case "/v2/projects/123/locations/-/instances":
						body = `{"instances":[{"name":"projects/123/locations/us-central1-a/instances/n"}]}`
					case "/v2/projects/123/locations/us-central1-a/instances/n":
						body = `{"name":"projects/123/locations/us-central1-a/instances/n","gceSetup":{"metadata":{"password":"` + value + `"}}}`
					default:
						t.Fatalf("unreviewed fixture request %s", r.URL)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			capture := inventory.NewSecretCapture(0, 0, 0)
			c := &inventory.Client{HTTP: &http.Client{Transport: transport}, TokenEnv: "GCPBUSTER_COVERAGE_TOKEN", SecretCapture: capture}
			snap := inventory.Snapshot{}
			c.CollectViewerParameterManager(context.Background(), &snap, "demo", "projects/123")
			c.CollectViewerDeploymentManager(context.Background(), &snap, "demo", "projects/123")
			c.CollectViewerNotebookSecrets(context.Background(), &snap, "demo", "projects/123")
			c.CollectViewerDataFusionSecrets(context.Background(), &snap, "demo", "projects/123")
			c.CollectViewerAppHosting(context.Background(), &snap, "demo", "projects/123")
			c.CollectViewerCloudDeploy(context.Background(), &snap, "demo", "projects/123")
			if len(capture.Samples()) != 13 || roles != 3 || calls != 29 {
				t.Fatalf("capture=%d roles=%d calls=%d coverage=%v", len(capture.Samples()), roles, calls, snap.Coverage)
			}
			for _, coverage := range snap.Coverage {
				if coverage.Status == "failed" || coverage.Status == "incomplete" {
					t.Fatal("collector coverage failure", coverage)
				}
			}
			encoded, _ := json.Marshal(snap)
			if bytes.Contains(encoded, []byte(value)) || bytes.Contains(encoded, []byte("DO_NOT_CAPTURE")) {
				t.Fatal("raw CDAP configuration persisted")
			}
			for _, a := range snap.Assets {
				if a.Type == inventory.DataFusionConnectionType || a.Type == inventory.DataFusionPipelineType {
					if len(a.Ancestors) != 1 || a.Ancestors[0] != "projects/123" {
						t.Fatal("CDAP project ancestry", a)
					}
				}
			}
			verifySecretsCoverageReports(t, &snap, capture, redact, value, 13)
		})
	}
}

func TestSecretsApprovedFamilyReportingMatrix(t *testing.T) {
	const value = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fixtures := []struct{ source, resource, path string }{
		{"function_env", "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/f", "environmentVariables.PASSWORD"},
		{"cloud_build_config", "//cloudbuild.googleapis.com/projects/demo/locations/global/builds/b", "steps[0].env[0]"},
		{"compute_instance_metadata", "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/v", "metadata.items[0].value"},
		{"run_config", "//run.googleapis.com/projects/demo/locations/us-central1/services/s", "template.containers[0].env[0].value"},
		{"workflow_execution", "//workflowexecutions.googleapis.com/projects/demo/locations/us-central1/workflows/w/executions/e", "argument"},
		{"secret_manager_annotations", "//secretmanager.googleapis.com/projects/123/secrets/s", "annotations.PASSWORD"},
		{"dataflow_config", "//dataflow.googleapis.com/projects/demo/locations/us-central1/jobs/j", "environment.sdkPipelineOptions.PASSWORD"},
		{"composer_config", "//composer.googleapis.com/projects/demo/locations/us-central1/environments/c", "config.softwareConfig.envVariables.PASSWORD"},
		{"vertex_pipeline_config", "//aiplatform.googleapis.com/projects/demo/locations/us-central1/pipelineJobs/p", "runtimeConfig.parameterValues.PASSWORD"},
		{"dataproc_metadata", "//dataproc.googleapis.com/projects/demo/regions/us-central1/clusters/c", "config.gceClusterConfig.metadata.PASSWORD"},
		{"clouddeploy_parameters", "//clouddeploy.googleapis.com/projects/demo/locations/us-central1/deliveryPipelines/p", "deployParameters.PASSWORD"},
		{"api_key_value", "//apikeys.googleapis.com/projects/123/locations/global/keys/k", "keyString"},
		{"apphosting_env", "//firebaseapphosting.googleapis.com/projects/demo/locations/us-central1/backends/b/builds/x", "config.effectiveEnv[0].value"},
		{"sql_database_flags", "//sqladmin.googleapis.com/projects/demo/instances/s", "settings.databaseFlags[0].value"},
		{"datafusion_options", "//datafusion.googleapis.com/projects/demo/locations/us-central1/instances/f", "options.PASSWORD"},
		{"workflow_revision_env", "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", "revisions[000001-abc].userEnvVars.PASSWORD"},
		{"run_revision_config", "//run.googleapis.com/projects/demo/locations/us-central1/services/s/revisions/s-00001-abc", "containers[0].env[0].value"},
		{"dns_record_config", "//dns.googleapis.com/projects/demo/managedZones/123/record-metadata/" + strings.Repeat("a", 64), "rrdatas[0].decoded"},
		{"dns_record_config", "//dns.googleapis.com/projects/demo/responsePolicies/456/rules/rule", "localData.localDatas[0].rrdatas[0].decoded"},
	}
	for _, redact := range []bool{false, true} {
		t.Run(fmt.Sprintf("redact=%v", redact), func(t *testing.T) {
			capture := inventory.NewSecretCapture(0, 0, 0)
			for _, f := range fixtures {
				key := "PASSWORD"
				if f.source == "api_key_value" {
					key = "API_KEY"
				}
				if !capture.Add(inventory.SecretSample{SourceType: f.source, Resource: f.resource, Path: f.path, Data: []byte(key + "=" + value)}) {
					t.Fatal("fixture rejected")
				}
			}
			snap := inventory.Snapshot{}
			verifySecretsCoverageReports(t, &snap, capture, redact, value, len(fixtures))
		})
	}
}

func TestSecretsDNSActualAndRedactedReports(t *testing.T) {
	const value = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, redact := range []bool{false, true} {
		t.Run(fmt.Sprintf("redact=%v", redact), func(t *testing.T) {
			capture := inventory.NewSecretCapture(0, 0, 0)
			capture.Add(inventory.SecretSample{SourceType: "dns_record_config", Resource: "//dns.googleapis.com/projects/demo/managedZones/123/record-metadata/" + strings.Repeat("a", 64), Path: "rrdatas[0].decoded", Data: []byte("password=" + value)})
			capture.Add(inventory.SecretSample{SourceType: "dns_record_config", Resource: "//dns.googleapis.com/projects/demo/responsePolicies/456/rules/rule", Path: "localData.localDatas[0].rrdatas[0].decoded", Data: []byte("password=" + value)})
			snap := inventory.Snapshot{}
			verifySecretsCoverageReports(t, &snap, capture, redact, value, 2)
		})
	}
}

func verifySecretsCoverageReports(t *testing.T, snap *inventory.Snapshot, capture *inventory.SecretCapture, redact bool, value string, want int) {
	t.Helper()
	runner := func(_ context.Context, input []kingfisher.Sample, options kingfisher.Options) (kingfisher.Report, error) {
		if options.Redact != redact || len(input) != want {
			t.Fatal("runner options")
		}
		r := kingfisher.Report{SamplesScanned: len(input)}
		for _, s := range input {
			if !strings.Contains(s.Content, value) {
				t.Fatal("collector value absent")
			}
			r.Findings = append(r.Findings, kingfisher.Finding{SampleID: s.ID, RuleID: "synthetic-token", RuleName: "Synthetic token", Snippet: value, Confidence: "high", Validation: "not_attempted", Line: 1})
		}
		return r, nil
	}
	prepareSecrets(context.Background(), snap, capture, redact, true, true, runner)
	native, scan := 0, 0
	for _, a := range snap.Assets {
		if source := inventory.Str(a.Resource.Data["source_type"]); source == "workflow_revision_env" || source == "run_revision_config" {
			if redact {
				if a.Resource.Data["source_revision"] != nil || a.Resource.Data["pull_command"] != nil {
					t.Fatal("redacted historical refetch metadata retained")
				}
			} else {
				expected := "000001-abc"
				if source == "run_revision_config" {
					expected = "s-00001-abc"
				}
				if a.Resource.Data["source_revision"] != expected {
					t.Fatal("missing exact historical revision", a.Resource.Data)
				}
				command := inventory.Str(a.Resource.Data["pull_command"])
				if !strings.Contains(command, expected) {
					t.Fatal("historical command lost revision", command)
				}
				if source == "workflow_revision_env" && !strings.Contains(command, "revisionId=000001-abc") {
					t.Fatal("workflow revision query lost", command)
				}
			}
		}
		if a.Type == checks.CapturedConfigurationValueType {
			native++
		}
		if a.Type == checks.SecretScanFindingType {
			scan++
			if !redact && a.Resource.Data["refetch_instruction"] == nil {
				t.Fatal("manual review instructions absent")
			}
			if command, ok := a.Resource.Data["pull_command"].(string); ok && (strings.Contains(command, ":access") || strings.Contains(command, ":render") || strings.Contains(command, value)) {
				t.Fatal("unsafe manual command")
			}
		}
		if source := inventory.Str(a.Resource.Data["source_type"]); source == "datafusion_connection_config" || source == "datafusion_pipeline_config" {
			if len(a.Ancestors) != 1 || a.Ancestors[0] != "projects/123" {
				t.Fatal("derived CDAP finding ancestry")
			}
			if !redact {
				command := inventory.Str(a.Resource.Data["pull_command"])
				if !strings.Contains(command, "https://etl-demo-dot-usc1.datafusion.googleusercontent.com/api/") || !strings.Contains(command, "--request GET") || !strings.Contains(command, "chosen") {
					t.Fatal("CDAP manual command lost verified origin or namespace", command)
				}
				if a.Resource.Data["refetch_instruction"] == nil {
					t.Fatal("missing CDAP manual refetch instruction")
				}
			}
		}
	}
	if native != want || scan != want {
		t.Fatalf("native=%d scanner=%d want=%d", native, scan, want)
	}
	selected, e := checks.Select([]string{"secrets_scan", "configuration_plaintext"}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	eng, e := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if e != nil {
		t.Fatal(e)
	}
	defer eng.Close()
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if e = assess(context.Background(), cmd, eng, *snap, selected, false); e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{"findings.json", "report.html", "engagement.db"} {
		data, e := os.ReadFile(filepath.Join(eng.Dir, file))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(data, []byte(value)) == redact {
			t.Fatalf("retention mismatch %s", file)
		}
	}
	var count int
	if e = eng.DB().QueryRow("SELECT count(*) FROM findings WHERE raw_output_path IS NOT NULL").Scan(&count); e != nil {
		t.Fatal(e)
	}
	expected := want * 2
	if redact {
		expected = 0
	}
	if count != expected {
		t.Fatalf("artifact refs=%d want=%d", count, expected)
	}
	artifacts := 0
	if e = filepath.WalkDir(eng.Dir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if strings.Contains(path, "/secret-hits/") {
			artifacts++
			info, e := d.Info()
			if e != nil {
				return e
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("insecure artifact mode")
			}
		}
		if redact {
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if bytes.Contains(data, []byte(value)) {
				t.Fatalf("redacted leak %s", path)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if redact && artifacts != 0 {
		t.Fatal("redacted source artifacts")
	}
	if !redact && artifacts != want {
		t.Fatalf("dedup artifacts=%d want=%d", artifacts, want)
	}
}
