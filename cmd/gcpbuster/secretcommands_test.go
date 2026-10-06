package main

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestSecretPullCommandsOnlyReviewedConfigurationReads(t *testing.T) {
	cases := []struct{ source, resource, location string }{
		{"parameter_manager_raw", "//parametermanager.googleapis.com/projects/123/locations/us-central1/parameters/p/versions/v", "us-central1"},
		{"deployment_manager_manifest", "//deploymentmanager.googleapis.com/projects/demo/global/deployments/d/manifests/m", "global"},
		{"workflow_definition", "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", "us-central1"},
		{"workflow_execution", "//workflowexecutions.googleapis.com/projects/demo/locations/us-central1/workflows/w/executions/e", "us-central1"},
		{"appengine_env", "//appengine.googleapis.com/apps/demo/services/s/versions/v", ""},
		{"api_key_value", "//apikeys.googleapis.com/projects/123/locations/global/keys/key", "global"},
		{"run_config", "//run.googleapis.com/projects/demo/locations/us-central1/services/s", "us-central1"},
		{"run_job_config", "//run.googleapis.com/projects/demo/locations/us-central1/jobs/j", "us-central1"},
		{"cloud_build_config", "//cloudbuild.googleapis.com/projects/demo/locations/us-central1/builds/b", "us-central1"},
		{"compute_project_metadata", "//compute.googleapis.com/projects/demo", ""},
		{"compute_instance_metadata", "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/i", "us-central1-a"},
		{"compute_template_metadata", "//compute.googleapis.com/projects/demo/global/instanceTemplates/t", "global"},
		{"compute_machine_image_metadata", "//compute.googleapis.com/projects/demo/global/machineImages/i", "global"},
		{"function_env", "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/f", "us-central1"},
		{"composer_config", "//composer.googleapis.com/projects/demo/locations/us-central1/environments/e", "us-central1"},
		{"dataflow_config", "//dataflow.googleapis.com/projects/demo/locations/us-central1/jobs/j", "us-central1"},
		{"scheduler_headers", "//cloudscheduler.googleapis.com/projects/demo/locations/us-central1/jobs/j", "us-central1"},
		{"workbench_metadata", "//notebooks.googleapis.com/projects/demo/locations/us-central1/instances/i", "us-central1"},
		{"datafusion_options", "//datafusion.googleapis.com/projects/demo/locations/us-central1/instances/i", "us-central1"},
		{"dataproc_args", "//dataproc.googleapis.com/projects/demo/regions/us-central1/jobs/j", "us-central1"},
		{"vertex_job_config", "//aiplatform.googleapis.com/projects/demo/locations/us-central1/customJobs/123", "us-central1"},
		{"vertex_pipeline_config", "//aiplatform.googleapis.com/projects/demo/locations/us-central1/pipelineJobs/123", "us-central1"},
		{"secret_manager_annotations", "//secretmanager.googleapis.com/projects/demo/secrets/s", "global"},
		{"clouddeploy_parameters", "//clouddeploy.googleapis.com/projects/demo/locations/us-central1/deliveryPipelines/p/releases/r", "us-central1"},
		{"apphosting_env", "//firebaseapphosting.googleapis.com/projects/demo/locations/us-central1/backends/b/builds/b1", "us-central1"},
		{"apigateway_openapi", "//apigateway.googleapis.com/projects/demo/locations/global/apis/a/configs/c", "global"},
		{"service_management_config", "//servicemanagement.googleapis.com/services/api.example.invalid/configs/123", ""},
		{"sql_database_flags", "//cloudsql.googleapis.com/projects/demo/instances/db", "us-central1"},
		{"dns_record_config", "//dns.googleapis.com/projects/demo/managedZones/123/record-metadata/" + strings.Repeat("a", 64), ""},
		{"dns_record_config", "//dns.googleapis.com/projects/demo/responsePolicies/policy/rules/rule", ""},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			sample := inventory.SecretSample{SourceType: tc.source, Resource: tc.resource, Location: tc.location, Data: []byte("SECRET_SENTINEL")}
			command := secretPullCommand(sample)
			if command == "" || tc.source != "api_key_value" && !strings.Contains(command, "--request GET") || strings.Contains(command, "SECRET_SENTINEL") || strings.Contains(command, "--impersonate") || strings.Contains(command, "--output") {
				t.Fatal(command)
			}
			endpoint, q := secretRefetchRequest(sample)
			if _, err := inventory.ViewerRequestPermissions("GET", endpoint, q); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecretPullCommandsRejectMalformedUnknownOrWrongLocation(t *testing.T) {
	for _, sample := range []inventory.SecretSample{
		{SourceType: "unknown", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w"},
		{SourceType: "workflow_definition", Resource: "//attacker.invalid/projects/demo/locations/us-central1/workflows/w"},
		{SourceType: "workflow_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w'$(touch evil)"},
		{SourceType: "workflow_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/%2e%2e"},
		{SourceType: "workflow_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w?fields=*"},
		{SourceType: "workflow_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", Location: "us-east1"},
		{SourceType: "api_key_value", Resource: "//apikeys.googleapis.com/projects/not-numeric/locations/us-east1/keys/key"},
	} {
		if command := secretPullCommand(sample); command != "" {
			t.Fatal("unsafe command", command)
		}
	}
	if quoted := secretShellQuote("a'b"); quoted != "'a'\"'\"'b'" {
		t.Fatal(quoted)
	}
}

func TestSecretLogRefetchIsBoundedReadWithPrivateExclusions(t *testing.T) {
	command := secretPullCommand(inventory.SecretSample{SourceType: "log_content", Resource: "//logging.googleapis.com/projects/demo/logs/app%2Fcomponent", Data: []byte("SECRET_SENTINEL")})
	if command == "" || !strings.Contains(command, "--request POST") || !strings.Contains(command, "entries:list") || !strings.Contains(command, "pageSize\":100") || !strings.Contains(command, "data_access") || strings.Contains(command, "SECRET_SENTINEL") {
		t.Fatal(command)
	}
	for _, name := range []string{"//logging.googleapis.com/projects/demo/logs/cloudaudit.googleapis.com%2Fdata_access", "//logging.googleapis.com/organizations/123/logs/application", "//logging.googleapis.com/projects/demo/logs/cloudaudit.googleapis.com%252Fdata_access"} {
		if secretPullCommand(inventory.SecretSample{SourceType: "log_content", Resource: name}) != "" {
			t.Fatal("private or unscoped log allowed", name)
		}
	}
}

func TestHistoricalRefetchPreservesWorkflowRevisionIdentity(t *testing.T) {
	command := secretPullCommand(inventory.SecretSample{SourceType: "workflow_revision_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", Location: "us-central1", Path: "revisions[000001-a4d].sourceContents"})
	if command == "" || !strings.Contains(command, "revisionId=000001-a4d") {
		t.Fatal(command)
	}
	if secretPullCommand(inventory.SecretSample{SourceType: "workflow_revision_definition", Resource: "//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/w", Path: "revisions[../other].sourceContents"}) != "" {
		t.Fatal("invalidrevision accepted")
	}
	command = secretPullCommand(inventory.SecretSample{SourceType: "run_revision_config", Resource: "//run.googleapis.com/projects/demo/locations/us-central1/services/s/revisions/s-00001-a4d", Location: "us-central1", Path: "containers[0].env[0].value"})
	if command == "" || !strings.Contains(command, "services/s/revisions/s-00001-a4d") {
		t.Fatal(command)
	}
	for _, path := range []string{"serviceAccount", "containers[0].image"} {
		sample := inventory.SecretSample{SourceType: "run_revision_config", Resource: "//run.googleapis.com/projects/demo/locations/us-central1/services/s/revisions/s-00001-a4d", Location: "us-central1", Path: path}
		command = secretPullCommand(sample)
		if command == "" || !strings.Contains(command, "services/s/revisions/s-00001-a4d") || !strings.Contains(command, "--request GET") || secretSourceRevision(sample) != "s-00001-a4d" {
			t.Fatal("revision context refetch lost identity", path, command)
		}
	}
}

func TestDNSRuleRefetchResolvesVerifiedParentNameOnly(t *testing.T) {
	sample := inventory.SecretSample{SourceType: "dns_record_config", Resource: "//dns.googleapis.com/projects/demo/responsePolicies/123/rules/rule", Path: "localData.localDatas[0].rrdatas[0]"}
	if secretPullCommandFromAssets(sample, nil) != "" {
		t.Fatal("numeric policy guessed")
	}
	parent := inventory.NewAsset("//dns.googleapis.com/projects/demo/responsePolicies/123", "dns.googleapis.com/ResponsePolicy", inventory.Object{"id": "123", "responsePolicyName": "policy"})
	command := secretPullCommandFromAssets(sample, []inventory.Asset{parent})
	if command == "" || !strings.Contains(command, "responsePolicies/policy/rules") {
		t.Fatal(command)
	}
	parent.Resource.Data["responsePolicyName"] = "policy?fields=*"
	if secretPullCommandFromAssets(sample, []inventory.Asset{parent}) != "" {
		t.Fatal("unsafeparent accepted")
	}
}
