package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

const CapturedConfigurationValueType = "gcpbuster.googleapis.com/CapturedConfigurationValue"

var capturedIndexedEnv = regexp.MustCompile(`^(?:build\.)?(?:steps\[[0-9]+\]\.env\[[0-9]+\]|options\.env\[[0-9]+\])$`)
var capturedRunEnv = regexp.MustCompile(`^template\.containers\[[0-9]+\]\.env\[[0-9]+\]\.value$`)
var capturedRunJobEnv = regexp.MustCompile(`^template\.template\.containers\[[0-9]+\]\.env\[[0-9]+\]\.value$`)
var capturedMetadata = regexp.MustCompile(`^(metadata|commonInstanceMetadata)\.items\[[0-9]+\]\.value$`)
var capturedMetadataKey = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var capturedVariablePlaceholder = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$`)
var capturedNativeEnvName = regexp.MustCompile(`^[^=\x00\r\n]+$`)
var capturedParameterResource = regexp.MustCompile(`^//parametermanager\.googleapis\.com/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/(?:parameters|templates)/([A-Za-z0-9_-]+)/versions/[A-Za-z0-9_-]+$`)
var capturedMapKey = regexp.MustCompile(`^[A-Za-z0-9_.!-]{1,128}$`)
var capturedDataprocKey = regexp.MustCompile(`^[A-Za-z0-9_.!:-]{1,128}$`)
var capturedCloudDeployMap = regexp.MustCompile(`^(deployParameters|(?:deliveryPipelineSnapshot\.)?serialPipeline\.stages\[[0-9]+\]\.deployParameters\[[0-9]+\]\.values|targetSnapshots\[[0-9]+\]\.deployParameters)$`)
var capturedDataprocMap = regexp.MustCompile(`^(config\.softwareConfig\.properties|placement\.managedCluster\.config\.softwareConfig\.properties|runtimeConfig\.properties|sparkSqlBatch\.queryVariables|(?:jobs\[[0-9]+\]\.)?(?:hadoopJob|sparkJob|pysparkJob|sparkRJob|flinkJob|hiveJob|pigJob|sparkSqlJob|prestoJob|trinoJob)\.(properties|scriptVariables))$`)
var capturedVertexEnv = regexp.MustCompile(`^jobSpec\.workerPoolSpecs\[[0-9]+\]\.containerSpec\[0\]\.env\[[0-9]+\]\.value$`)
var capturedTemplateMetadata = regexp.MustCompile(`^(properties|instanceProperties)\.metadata\.items\[[0-9]+\]\.value$`)
var capturedDataflowMap = regexp.MustCompile(`^steps\[[0-9]+\]\.properties$`)
var capturedNestedDataflow = regexp.MustCompile(`^(environment\.sdkPipelineOptions|steps\[[0-9]+\]\.properties)\.[A-Za-z0-9_.!\[\]-]+$`)
var capturedPipelineEnv = regexp.MustCompile(`^pipelineSpec\.deploymentSpec\.executors\.[A-Za-z0-9_-]+\.container\[0\]\.env\[[0-9]+\]\.value$`)
var capturedPipelineValues = regexp.MustCompile(`^(runtimeConfig\.(parameterValues|parameters)\.[A-Za-z0-9_.!\[\]-]+|pipelineSpec\.(components\.[A-Za-z0-9_-]+|root)\.(inputDefinitions\.parameters\.[A-Za-z0-9_-]+\.defaultValue|dag\.tasks\.[A-Za-z0-9_-]+\.inputs\.parameters\.[A-Za-z0-9_-]+\.runtimeValue\.constant)(\.[A-Za-z0-9_.!\[\]-]+|\[[0-9]+\])?)$`)
var capturedLiteralPaths = map[string]*regexp.Regexp{
	"apigee_bundle_config":         regexp.MustCompile(`^bundle\[(apiproxy|sharedflowbundle)/(policies|proxies|targets|sharedflows)/[A-Za-z0-9_. -]{1,255}\.xml\]\.xml$`),
	"dns_record_config":            regexp.MustCompile(`^(localData\.localDatas\[[0-9]+\]\.)?(rrdatas\[[0-9]+\](\.decoded)?|routingPolicy\.healthCheck|routingPolicy\.(geo|wrr|primaryBackup\.backupGeo)\.items\[[0-9]+\]\.(rrdatas\[[0-9]+\](\.decoded)?|healthCheckedTargets\.(externalEndpoints\[[0-9]+\]|internalLoadBalancers\[[0-9]+\]\.(ipAddress|port|networkUrl)))|routingPolicy\.primaryBackup\.primaryTargets\.(externalEndpoints\[[0-9]+\]|internalLoadBalancers\[[0-9]+\]\.(ipAddress|port|networkUrl)))$`),
	"workflow_revision_definition": regexp.MustCompile(`^revisions\[[0-9]{6}-[a-f0-9]{3}\]\.sourceContents$`),
	"run_revision_config":          regexp.MustCompile(`^containers\[[0-9]+\]\.(command|args)\[[0-9]+\]$`),
	"dataproc_args":                regexp.MustCompile(`^(jobs\[[0-9]+\]\.)?(hadoopJob|sparkJob|pysparkJob|sparkRJob|flinkJob|hiveJob|pigJob|sparkSqlJob|prestoJob|trinoJob|pysparkBatch|sparkBatch|sparkRBatch)\.args\[[0-9]+\]$`),
	"dataproc_query":               regexp.MustCompile(`^(jobs\[[0-9]+\]\.)?(hiveJob|pigJob|sparkSqlJob|prestoJob|trinoJob)\.queryList\.queries\[[0-9]+\]$`),
	"parameter_manager_raw":        regexp.MustCompile(`^payload\.data$`),
	"parameter_template_raw":       regexp.MustCompile(`^payload\.data$`),
	"workflow_execution":           regexp.MustCompile(`^(argument|result|error\.payload)$`),
	"deployment_manager_manifest":  regexp.MustCompile(`^(config\.content|imports\[[0-9]+\]\.content|expandedConfig|layout)$`),
	"vertex_pipeline_config":       regexp.MustCompile(`^pipelineSpec\.deploymentSpec\.executors\.[A-Za-z0-9_-]+\.container\[0\]\.(command|args)\[[0-9]+\]$`),
	"run_config":                   regexp.MustCompile(`^template\.containers\[[0-9]+\]\.(command|args)\[[0-9]+\]$`),
	"run_job_config":               regexp.MustCompile(`^template\.template\.containers\[[0-9]+\]\.(command|args)\[[0-9]+\]$`),
	"cloud_build_config":           regexp.MustCompile(`^(build\.)?steps\[[0-9]+\]\.(script|args\[[0-9]+\])$`),
	"vertex_job_config":            regexp.MustCompile(`^jobSpec\.workerPoolSpecs\[[0-9]+\]\.(containerSpec\[0\]\.(command|args)\[[0-9]+\]|pythonPackageSpec\.args\[[0-9]+\])$`),
	"workflow_definition":          regexp.MustCompile(`^sourceContents$`),
	"apigateway_openapi":           regexp.MustCompile(`^openapiDocuments\[[0-9]+\]\.document\.contents$`),
	"service_management_config":    regexp.MustCompile(`^(authentication\.providers\[[0-9]+\]\.(id|issuer)|backend\.rules\[[0-9]+\]\.(selector|address|jwtAudience))$`),
	"scheduler_config":             regexp.MustCompile(`^(httpTarget\.uri|appEngineHttpTarget\.relativeUri)$`),
}

func capturedLiteralPath(source, path string) bool {
	rule := capturedLiteralPaths[source]
	return len(path) <= 2048 && rule != nil && rule.MatchString(path)
}

func capturedAssignmentPath(source, path, key string) bool {
	if len(path) > 2048 || len(key) > 1024 {
		return false
	}
	switch source {
	case "apigee_bundle_config":
		return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`).MatchString(key) && regexp.MustCompile(`^bundle\[(apiproxy|sharedflowbundle)/(policies|proxies|targets|sharedflows)/[A-Za-z0-9_. -]{1,255}\.xml\]\.xml\.elements\[[0-9]+\]\.`).MatchString(path) && strings.HasSuffix(path, "."+key)
	case "workflow_revision_env":
		return capturedNativeEnvName.MatchString(key) && regexp.MustCompile(`^revisions\[[0-9]{6}-[a-f0-9]{3}\]\.userEnvVars\.`).MatchString(path) && strings.HasSuffix(path, "."+key)
	case "run_revision_config":
		return (key == "serviceAccount" && path == "serviceAccount") || (key == "image" && regexp.MustCompile(`^containers\[[0-9]+\]\.image$`).MatchString(path)) || (capturedNativeEnvName.MatchString(key) && regexp.MustCompile(`^containers\[[0-9]+\]\.env\[[0-9]+\]\.value$`).MatchString(path))
	case "run_context":
		return (key == "serviceAccount" && (path == "template.serviceAccount" || path == "template.template.serviceAccount")) || (key == "image" && regexp.MustCompile(`^template\.(template\.)?containers\[[0-9]+\]\.image$`).MatchString(path))
	case "appengine_env":
		return capturedNativeEnvName.MatchString(key) && path == "envVariables."+key
	case "appengine_build_env":
		return capturedNativeEnvName.MatchString(key) && path == "buildEnvVariables."+key
	case "function_env":
		return capturedNativeEnvName.MatchString(key) && (path == "environmentVariables."+key || path == "serviceConfig.environmentVariables."+key)
	case "function_build_env":
		return capturedNativeEnvName.MatchString(key) && (path == "buildEnvironmentVariables."+key || path == "buildConfig.environmentVariables."+key)
	case "workflow_env":
		return capturedNativeEnvName.MatchString(key) && path == "userEnvVars."+key
	case "run_config":
		return capturedNativeEnvName.MatchString(key) && capturedRunEnv.MatchString(path)
	case "run_job_config":
		return capturedNativeEnvName.MatchString(key) && capturedRunJobEnv.MatchString(path)
	case "cloud_build_config":
		return capturedNativeEnvName.MatchString(key) && (capturedIndexedEnv.MatchString(path) || path == "substitutions."+key || path == "build.substitutions."+key)
	case "compute_instance_metadata":
		return capturedMetadataKey.MatchString(key) && strings.HasPrefix(path, "metadata.") && capturedMetadata.MatchString(path)
	case "compute_project_metadata":
		return capturedMetadataKey.MatchString(key) && strings.HasPrefix(path, "commonInstanceMetadata.") && capturedMetadata.MatchString(path)
	case "compute_template_metadata":
		return capturedMetadataKey.MatchString(key) && strings.HasPrefix(path, "properties.") && capturedTemplateMetadata.MatchString(path)
	case "compute_machine_image_metadata":
		return capturedMetadataKey.MatchString(key) && strings.HasPrefix(path, "instanceProperties.") && capturedTemplateMetadata.MatchString(path)
	case "vertex_job_config":
		return capturedNativeEnvName.MatchString(key) && capturedVertexEnv.MatchString(path)
	case "composer_config":
		return capturedMapKey.MatchString(key) && (path == "config.softwareConfig.envVariables."+key || path == "config.softwareConfig.airflowConfigOverrides."+key || path == "config.softwareConfig.pypiPackages."+key)
	case "scheduler_headers":
		return capturedMapKey.MatchString(key) && (path == "httpTarget.headers."+key || path == "appEngineHttpTarget.headers."+key)
	case "dataflow_config":
		base := strings.TrimSuffix(path, "."+key)
		return capturedMapKey.MatchString(key) && ((base != path && (base == "environment.sdkPipelineOptions" || capturedDataflowMap.MatchString(base))) || capturedNestedDataflow.MatchString(path))
	case "secret_manager_annotations":
		return capturedMapKey.MatchString(key) && path == "annotations."+key
	case "api_key_value":
		return key == "API_KEY" && path == "keyString"
	case "apphosting_env":
		return capturedNativeEnvName.MatchString(key) && regexp.MustCompile(`^config\.effectiveEnv\[[0-9]+\]\.value$`).MatchString(path)
	case "sql_database_flags":
		return capturedDataprocKey.MatchString(key) && regexp.MustCompile(`^settings\.databaseFlags\[[0-9]+\]\.value$`).MatchString(path)
	case "datafusion_options":
		return capturedMapKey.MatchString(key) && path == "options."+key
	case "datafusion_connection_config":
		return capturedMapKey.MatchString(key) && path == "plugin.properties."+key
	case "datafusion_pipeline_config":
		base := strings.TrimSuffix(path, "."+key)
		return capturedMapKey.MatchString(key) && (base == "configuration.properties" || regexp.MustCompile(`^configuration\.(stages|postActions)\[[0-9]+\]\.plugin\.properties$`).MatchString(base))
	case "workbench_metadata":
		return capturedMapKey.MatchString(key) && path == "gceSetup.metadata."+key
	case "clouddeploy_parameters":
		return capturedMapKey.MatchString(key) && capturedCloudDeployMap.MatchString(strings.TrimSuffix(path, "."+key))
	case "dataproc_metadata":
		return capturedMapKey.MatchString(key) && (path == "config.gceClusterConfig.metadata."+key || path == "placement.managedCluster.config.gceClusterConfig.metadata."+key)
	case "dataproc_properties":
		return capturedDataprocKey.MatchString(key) && capturedDataprocMap.MatchString(strings.TrimSuffix(path, "."+key))
	case "vertex_pipeline_config":
		return (capturedNativeEnvName.MatchString(key) && capturedPipelineEnv.MatchString(path)) || (capturedMapKey.MatchString(key) && capturedPipelineValues.MatchString(path))
	}
	return false
}

// CapturedSampleAssets emits native plaintext inventory independently of the
// external scanner. Only explicitly captured assignment leaves are parsed;
// script/source/argument strings containing '=' are not environment variables.
func CapturedSampleAssets(samples []inventory.SecretSample, redact bool) []inventory.Asset {
	out := []inventory.Asset{}
	for _, sample := range samples {
		if len(sample.Data) > 4<<20 || !utf8.Valid(sample.Data) || !strings.HasPrefix(sample.Resource, "//") {
			continue
		}
		key, value, ok := strings.Cut(string(sample.Data), "=")
		kind := "assignment"
		if !ok || !capturedAssignmentPath(sample.SourceType, sample.Path, key) {
			if !capturedLiteralPath(sample.SourceType, sample.Path) {
				continue
			}
			kind = "literal"
			key = ""
			value = string(sample.Data)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "[REDACTED]" {
			continue
		}
		credentialCandidate := trimmed != "" && !secretReference.MatchString(trimmed) && !secretPlaceholder.MatchString(trimmed) && !capturedVariablePlaceholder.MatchString(trimmed) && !parameterReferenceExpression(trimmed)
		reasons := []any{}
		if (sample.SourceType == "parameter_manager_raw" || sample.SourceType == "parameter_template_raw") && credentialCandidate && candidate(value) {
			if parts := capturedParameterResource.FindStringSubmatch(sample.Resource); len(parts) == 2 && secretName.MatchString(parts[1]) {
				reasons = append(reasons, "sensitive_parameter_name")
			}
		}
		if kind == "assignment" && credentialCandidate && candidate(value) && secretName.MatchString(key) {
			reasons = append(reasons, "sensitive_variable_name")
		}
		if credentialCandidate && candidate(value) && (secretValue.MatchString(value) || len(secretmatch.Text([]byte(value), "")) > 0) {
			reasons = append(reasons, "credential_pattern")
		}
		severity := "info"
		if kind == "literal" && len(reasons) == 0 && sample.SourceType != "workflow_execution" && sample.SourceType != "parameter_manager_raw" && sample.SourceType != "parameter_template_raw" {
			continue
		}
		if len(reasons) > 0 {
			severity = "high"
		}
		id := sample.ID
		if !secretNameDigest.MatchString(id) {
			h := sha256.New()
			for _, part := range []string{sample.SourceType, sample.Resource, sample.Location, sample.Path} {
				h.Write([]byte(part))
				h.Write([]byte{0})
			}
			id = hex.EncodeToString(h.Sum(nil))
		}
		resource, path := sample.Resource, sample.Path
		if redact {
			resource = "[REDACTED]"
			path = "[REDACTED]"
			key = "[REDACTED]"
			value = "[REDACTED]"
		}
		d := inventory.Object{"sample_id": id, "source_type": sample.SourceType, "source": resource, "field": path, "variable": key, "value": value, "severity": severity, "reasons": reasons, "redacted": redact, "credential_validation_performed": false, "record_kind": kind}
		out = append(out, inventory.NewAsset("//gcpbuster.googleapis.com/captured-configuration/"+id, CapturedConfigurationValueType, d))
	}
	return out
}

func capturedConfigurationValue(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	if a.Type != CapturedConfigurationValueType || d["credential_validation_performed"] != false || !secretNameDigest.MatchString(s(d["sample_id"])) {
		return nil
	}
	redacted, ok := d["redacted"].(bool)
	if !ok {
		return nil
	}
	switch d["source_type"] {
	case "apigee_bundle_config":
	case "parameter_template_raw":
	case "dns_record_config":
	case "workflow_revision_definition", "workflow_revision_env", "run_revision_config":
	case "run_context":
	case "dataproc_metadata", "dataproc_properties", "dataproc_args", "dataproc_query":
	case "api_key_value", "workbench_metadata", "clouddeploy_parameters", "apphosting_env":
	case "sql_database_flags", "datafusion_options":
	case "datafusion_connection_config", "datafusion_pipeline_config":
	case "appengine_env", "appengine_build_env", "function_env", "function_build_env", "workflow_env", "run_config", "run_job_config", "cloud_build_config", "compute_instance_metadata", "compute_project_metadata", "compute_template_metadata", "compute_machine_image_metadata", "vertex_job_config", "composer_config", "scheduler_headers", "dataflow_config", "workflow_definition", "apigateway_openapi", "service_management_config", "scheduler_config", "parameter_manager_raw", "workflow_execution", "deployment_manager_manifest", "secret_manager_annotations", "vertex_pipeline_config":
	default:
		return nil
	}
	value, vok := d["value"].(string)
	variable, nok := d["variable"].(string)
	if !vok || !nok || len(value) > 4<<20 || (d["severity"] != "high" && d["severity"] != "info") {
		return nil
	}
	kind := s(d["record_kind"])
	if kind != "assignment" && kind != "literal" {
		return nil
	}
	if kind == "literal" && d["severity"] != "high" && d["source_type"] != "workflow_execution" && d["source_type"] != "parameter_manager_raw" && d["source_type"] != "parameter_template_raw" {
		return nil
	}
	if redacted {
		if value != "[REDACTED]" || variable != "[REDACTED]" || d["source"] != "[REDACTED]" || d["field"] != "[REDACTED]" {
			return nil
		}
	} else {
		if kind == "assignment" && !capturedAssignmentPath(s(d["source_type"]), s(d["field"]), variable) {
			return nil
		}
		if kind == "literal" && (variable != "" || !capturedLiteralPath(s(d["source_type"]), s(d["field"]))) {
			return nil
		}
	}
	reasons, ok := d["reasons"].([]any)
	if !ok || len(reasons) > 2 {
		return nil
	}
	for _, reason := range reasons {
		if reason != "sensitive_variable_name" && reason != "sensitive_parameter_name" && reason != "credential_pattern" {
			return nil
		}
	}
	if (len(reasons) > 0) != (d["severity"] == "high") {
		return nil
	}
	evidence := inventory.Object{"assessment": "Explicit plaintext configuration; native heuristics only, no credential validation performed."}
	for _, field := range []string{"sample_id", "source_type", "source", "field", "variable", "value", "reasons", "redacted", "credential_validation_performed", "record_kind"} {
		evidence[field] = d[field]
	}
	if !redacted {
		if revision, ok := d["source_revision"].(string); ok && revision != "" {
			evidence["source_revision"] = revision
		}
		if instruction, ok := d["refetch_instruction"].(string); ok && instruction != "" {
			evidence["refetch_instruction"] = instruction
		}
		if location, ok := d["source_location"].(string); ok && location != "" {
			evidence["source_location"] = location
		}
		if metadata := inventory.Obj(d["refetch_metadata"]); metadata != nil {
			evidence["refetch_metadata"] = metadata
		}
		if command, ok := d["pull_command"].(string); ok && command != "" {
			evidence["pull_command"] = command
		}
	}
	title := "Plaintext configuration value available for manual review"
	if d["severity"] == "high" {
		title = "Potential secret in plaintext configuration"
	}
	return result(s(d["severity"]), title, "Review the protected value manually; rotate confirmed exposed secrets and use managed secret references where supported.", evidence)
}
