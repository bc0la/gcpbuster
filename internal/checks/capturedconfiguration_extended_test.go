package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestCapturedConfigurationNewSecretSources(t *testing.T) {
	for _, tc := range []struct{ source, path string }{
		{"parameter_manager_raw", "payload.data"},
		{"workflow_execution", "argument"},
		{"workflow_execution", "result"},
		{"workflow_execution", "error.payload"},
		{"dns_record_config", "rrdatas[0]"},
		{"dns_record_config", "localData.localDatas[1].rrdatas[0].decoded"},
		{"dns_record_config", "routingPolicy.wrr.items[0].rrdatas[1]"},
		{"workflow_revision_definition", "revisions[000001-a4d].sourceContents"},
		{"run_revision_config", "containers[0].args[1]"},
		{"deployment_manager_manifest", "config.content"},
		{"deployment_manager_manifest", "imports[2].content"},
		{"deployment_manager_manifest", "expandedConfig"},
		{"deployment_manager_manifest", "layout"},
		{"dataproc_args", "jobs[0].sparkJob.args[1]"},
		{"dataproc_query", "hiveJob.queryList.queries[0]"},
	} {
		const value = "url: https://user:long-synthetic-password@example.invalid/path\n"
		for _, redact := range []bool{false, true} {
			assets := CapturedSampleAssets([]inventory.SecretSample{{SourceType: tc.source, Path: tc.path, Resource: "//example.googleapis.com/r", Data: []byte(value)}}, redact)
			if len(assets) != 1 {
				t.Fatal(tc, assets)
			}
			results := capturedConfigurationValue(assets[0], time.Time{})
			if len(results) != 1 || results[0].Severity != "high" {
				t.Fatal(tc, results)
			}
			want := value
			if redact {
				want = "[REDACTED]"
			}
			if results[0].Evidence["value"] != want {
				t.Fatal("source value changed", tc)
			}
		}
	}
	for _, tc := range []struct{ source, path, key string }{
		{"secret_manager_annotations", "annotations.password", "password"},
		{"workflow_revision_env", "revisions[000001-a4d].userEnvVars.PASSWORD", "PASSWORD"},
		{"run_revision_config", "containers[0].env[0].value", "PASSWORD"},
		{"api_key_value", "keyString", "API_KEY"},
		{"apphosting_env", "config.effectiveEnv[0].value", "PASSWORD"},
		{"datafusion_options", "options.password", "password"},
		{"datafusion_connection_config", "plugin.properties.password", "password"},
		{"datafusion_pipeline_config", "configuration.stages[0].plugin.properties.password", "password"},
		{"datafusion_pipeline_config", "configuration.postActions[1].plugin.properties.password", "password"},
		{"sql_database_flags", "settings.databaseFlags[0].value", "password"},
		{"workbench_metadata", "gceSetup.metadata.password", "password"},
		{"dataproc_properties", "config.softwareConfig.properties.spark:password", "spark:password"},
		{"dataproc_properties", "jobs[0].hiveJob.scriptVariables.password", "password"},
		{"clouddeploy_parameters", "deployParameters.password", "password"},
		{"clouddeploy_parameters", "deliveryPipelineSnapshot.serialPipeline.stages[0].deployParameters[1].values.password", "password"},
		{"clouddeploy_parameters", "targetSnapshots[0].deployParameters.password", "password"},
		{"dataflow_config", "environment.sdkPipelineOptions.database.password", "password"},
		{"vertex_pipeline_config", "runtimeConfig.parameterValues.password", "password"},
		{"vertex_pipeline_config", "pipelineSpec.root.inputDefinitions.parameters.password.defaultValue", "password"},
		{"vertex_pipeline_config", "pipelineSpec.root.dag.tasks.task.inputs.parameters.password.runtimeValue.constant", "password"},
		{"vertex_pipeline_config", "pipelineSpec.deploymentSpec.executors.exec.container[0].env[0].value", "PASSWORD"},
	} {
		assets := CapturedSampleAssets([]inventory.SecretSample{{SourceType: tc.source, Path: tc.path, Resource: "//example.googleapis.com/r", Data: []byte(tc.key + "=long-synthetic-value")}}, false)
		if len(assets) != 1 || len(capturedConfigurationValue(assets[0], time.Time{})) != 1 {
			t.Fatal(tc, assets)
		}
	}
}

func TestCapturedConfigurationAdditionalAssignments(t *testing.T) {
	for _, tc := range []struct{ source, path, key string }{
		{"composer_config", "config.softwareConfig.envVariables.NORMAL", "NORMAL"},
		{"composer_config", "config.softwareConfig.airflowConfigOverrides.core-setting", "core-setting"},
		{"composer_config", "config.softwareConfig.pypiPackages.package-name", "package-name"},
		{"vertex_job_config", "jobSpec.workerPoolSpecs[0].containerSpec[0].env[2].value", "NORMAL"},
		{"compute_template_metadata", "properties.metadata.items[0].value", "startup-script"},
		{"compute_machine_image_metadata", "instanceProperties.metadata.items[0].value", "NORMAL"},
		{"scheduler_headers", "httpTarget.headers.Accept", "Accept"},
		{"scheduler_headers", "appEngineHttpTarget.headers.X-Custom", "X-Custom"},
		{"dataflow_config", "environment.sdkPipelineOptions.option_name", "option_name"},
		{"dataflow_config", "steps[3].properties.custom.option", "custom.option"},
	} {
		s := inventory.SecretSample{SourceType: tc.source, Path: tc.path, Resource: "//example.googleapis.com/r", Data: []byte(tc.key + "=normal multiline\nvalue=preserved")}
		a := CapturedSampleAssets([]inventory.SecretSample{s}, false)
		if len(a) != 1 {
			t.Fatal(tc, a)
		}
		got := capturedConfigurationValue(a[0], time.Time{})
		if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["value"] != "normal multiline\nvalue=preserved" {
			t.Fatal(tc, got)
		}
	}
}

func TestCapturedConfigurationApprovedLiteralCandidatesOnly(t *testing.T) {
	for _, tc := range []struct{ source, path string }{
		{"run_config", "template.containers[0].args[2]"},
		{"run_job_config", "template.template.containers[0].command[0]"},
		{"cloud_build_config", "build.steps[1].script"},
		{"cloud_build_config", "steps[0].args[1]"},
		{"vertex_job_config", "jobSpec.workerPoolSpecs[0].containerSpec[0].args[1]"},
		{"vertex_job_config", "jobSpec.workerPoolSpecs[0].pythonPackageSpec.args[1]"},
		{"workflow_definition", "sourceContents"},
		{"apigateway_openapi", "openapiDocuments[0].document.contents"},
		{"service_management_config", "backend.rules[0].address"},
		{"service_management_config", "authentication.providers[0].issuer"},
		{"scheduler_config", "httpTarget.uri"},
		{"scheduler_config", "appEngineHttpTarget.relativeUri"},
	} {
		value := "prefix\npassword=synthetic-long-candidate\ntrailing"
		s := inventory.SecretSample{SourceType: tc.source, Path: tc.path, Resource: "//example.googleapis.com/r", Data: []byte(value)}
		for _, redact := range []bool{false, true} {
			a := CapturedSampleAssets([]inventory.SecretSample{s}, redact)
			if len(a) != 1 {
				t.Fatal(tc, a)
			}
			got := capturedConfigurationValue(a[0], time.Time{})
			if len(got) != 1 || got[0].Severity != "high" || got[0].Evidence["record_kind"] != "literal" {
				t.Fatal(tc, got)
			}
			if !redact && (got[0].Evidence["value"] != value || got[0].Evidence["variable"] != "") {
				t.Fatal("source parsed as env", got)
			}
			if redact {
				b, _ := json.Marshal([]any{a, got})
				if strings.Contains(string(b), "synthetic-long-candidate") || strings.Contains(string(b), tc.path) {
					t.Fatal(string(b))
				}
			}
		}
		s.Data = []byte("ordinary source with A=B")
		if a := CapturedSampleAssets([]inventory.SecretSample{s}, false); len(a) != 0 {
			t.Fatal("ordinary source emitted", a)
		}
		s.Data = []byte(value)
		s.Path += ".unknown"
		if a := CapturedSampleAssets([]inventory.SecretSample{s}, false); len(a) != 0 {
			t.Fatal("unknown path emitted", a)
		}
	}
}

func TestCapturedConfigurationSharedMatcherAndProtectedReferences(t *testing.T) {
	s := inventory.SecretSample{SourceType: "scheduler_config", Path: "httpTarget.uri", Resource: "//example.googleapis.com/r", Data: []byte("https://user:synthetic-pass@example.invalid")}
	if got := CapturedSampleAssets([]inventory.SecretSample{s}, false); len(got) != 1 {
		t.Fatal("URL credential matcher omitted", got)
	}
	for _, value := range []string{"projects/demo/secrets/name/versions/latest", "${VARIABLE}", "$VARIABLE", "[REDACTED]"} {
		s.Data = []byte(value)
		if got := CapturedSampleAssets([]inventory.SecretSample{s}, false); len(got) != 0 {
			t.Fatal("protected/reference emitted", got)
		}
	}
}
