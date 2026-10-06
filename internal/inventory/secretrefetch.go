package inventory

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SecretLogRefetchBody repeats only the exact public log-name context using
// the same mandatory private-audit exclusions as collection. It is report data,
// not an executed request; a bounded page may not contain the original entry.
func SecretLogRefetchBody(s SecretSample) string {
	if s.SourceType != "log_content" || !strings.HasPrefix(s.Resource, "//logging.googleapis.com/projects/") {
		return ""
	}
	name := strings.TrimPrefix(s.Resource, "//logging.googleapis.com/")
	if strings.ContainsAny(name, "\x00\r\n\t\\") {
		return ""
	}
	p := strings.SplitN(name, "/logs/", 2)
	if len(p) != 2 || !regexp.MustCompile(`^projects/[A-Za-z0-9_-]+$`).MatchString(p[0]) {
		return ""
	}
	private, err := viewerLogEntry(name)
	if err != nil || private {
		return ""
	}
	filter, err := viewerLogFilter("logName=" + strconv.Quote(name))
	if err != nil {
		return ""
	}
	if _, err := viewerRequestPermissions("POST", "https://logging.googleapis.com/v2/entries:list", nil); err != nil {
		return ""
	}
	data, err := json.Marshal(Object{"resourceNames": []string{p[0]}, "filter": filter, "pageSize": 100, "orderBy": "timestamp desc"})
	if err != nil {
		return ""
	}
	return string(data)
}

// SecretRefetchRequest describes an already-reviewed configuration read for
// manual reporting. It performs no request or authorization assertion. A list
// refetch is its first page; operators must locate the reported source name and
// follow nextPageToken themselves. Original field/location evidence remains
// authoritative. Resource references embedded in values are never followed.
func SecretRefetchRequest(s SecretSample) (string, url.Values) {
	if !strings.HasPrefix(s.Resource, "//") || strings.ContainsAny(s.Resource, "%?#\\\x00\r\n\t '") || strings.Contains(s.Resource, "..") {
		return "", nil
	}
	parts := strings.SplitN(strings.TrimPrefix(s.Resource, "//"), "/", 2)
	if len(parts) != 2 {
		return "", nil
	}
	host, path := parts[0], parts[1]
	segments := strings.Split(path, "/")
	if len(segments) > 3 && segments[0] == "projects" && (segments[2] == "locations" || segments[2] == "regions" || segments[2] == "zones") && s.Location != "" && s.Location != segments[3] {
		return "", nil
	}
	q := url.Values{}
	const id = `[A-Za-z0-9_-]+`
	const regional = `projects/` + id + `/locations/[a-z][a-z0-9-]*/`
	valid := func(pattern string) bool { return regexp.MustCompile("^" + pattern + "$").MatchString(path) }
	version := "v1"
	switch s.SourceType {
	case "apigateway_openapi":
		if host != "apigateway.googleapis.com" || !valid(`projects/`+id+`/locations/global/apis/`+id+`/configs/`+id) {
			return "", nil
		}
		q.Set("view", "FULL")
		q.Set("fields", viewerAPIGatewayFullFields)
	case "service_management_config":
		if host != "servicemanagement.googleapis.com" || !valid(`services/[A-Za-z0-9_.-]+/configs/`+id) {
			return "", nil
		}
		q.Set("view", "BASIC")
		q.Set("fields", viewerServiceConfigFields)
	case "workflow_revision_definition", "workflow_revision_env":
		if host != "workflows.googleapis.com" || !valid(regional+`workflows/`+id) {
			return "", nil
		}
		parts := regexp.MustCompile(`^revisions\[([0-9]{6}-[a-f0-9]{3})\]\.(sourceContents|userEnvVars\..+)$`).FindStringSubmatch(s.Path)
		if len(parts) != 3 {
			return "", nil
		}
		q.Set("revisionId", parts[1])
		q.Set("fields", workflowRevisionConfigFields)
	case "run_revision_config":
		if host != "run.googleapis.com" || !valid(regional+`services/`+id+`/revisions/`+id) {
			return "", nil
		}
		version = "v2"
		q.Set("fields", runRevisionDetailFields)
	case "sql_database_flags":
		if host != "cloudsql.googleapis.com" || !valid(`projects/`+id+`/instances/`+id) {
			return "", nil
		}
		host = "sqladmin.googleapis.com"
		path = path[:strings.LastIndex(path, "/")]
		q.Set("maxResults", "1000")
	case "dns_record_config":
		if host != "dns.googleapis.com" {
			return "", nil
		}
		if valid(`projects/` + id + `/managedZones/[0-9]+/record-metadata/[a-f0-9]{64}`) {
			p := strings.Split(path, "/")
			path = strings.Join(p[:4], "/") + "/rrsets"
			q.Set("fields", viewerDNSRecordFields)
		} else if valid(`projects/` + id + `/responsePolicies/[a-z][a-z0-9-]*/rules/` + id) {
			path = path[:strings.LastIndex(path, "/")]
			q.Set("fields", viewerDNSResponseRuleFields)
		} else {
			return "", nil
		}
		version = "dns/v1"
		q.Set("maxResults", "100")
	case "compute_project_metadata":
		if host != "compute.googleapis.com" || !valid(`projects/`+id) {
			return "", nil
		}
		q.Set("fields", secretCaptureComputeProjectFields)
		version = "compute/v1"
	case "compute_instance_metadata":
		if host != "compute.googleapis.com" || !valid(`projects/`+id+`/zones/[a-z][a-z0-9-]*/instances/`+id) {
			return "", nil
		}
		if s.Location != "" && s.Location != strings.Split(path, "/")[3] {
			return "", nil
		}
		path = strings.Join(strings.Split(path, "/")[:2], "/") + "/aggregated/instances"
		q.Set("maxResults", "500")
		q.Set("returnPartialSuccess", "true")
		q.Set("fields", "items/*/instances("+secretCaptureComputeInstanceFields+"),items/*/warning,items/*/error,nextPageToken,warning,unreachables")
		version = "compute/v1"
	case "compute_template_metadata":
		if host != "compute.googleapis.com" || !valid(`projects/`+id+`/(global|regions/[a-z][a-z0-9-]*)/instanceTemplates/`+id) {
			return "", nil
		}
		path = strings.Join(strings.Split(path, "/")[:2], "/") + "/aggregated/instanceTemplates"
		q.Set("maxResults", "100")
		q.Set("returnPartialSuccess", "true")
		q.Set("fields", "items/*/instanceTemplates("+secretCaptureTemplateFields+"),items/*/warning,items/*/error,nextPageToken,warning,unreachables")
		version = "compute/v1"
	case "compute_machine_image_metadata":
		if host != "compute.googleapis.com" || !valid(`projects/`+id+`/global/machineImages/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("maxResults", "100")
		q.Set("fields", "items("+secretCaptureMachineImageFields+"),nextPageToken,warning")
		version = "compute/v1"
	case "function_env", "function_build_env":
		if host != "cloudfunctions.googleapis.com" || !valid(regional+`functions/`+id) {
			return "", nil
		}
		fields := secretCaptureFunctionV1Fields
		if strings.HasPrefix(s.Path, "serviceConfig.") || strings.HasPrefix(s.Path, "buildConfig.") {
			version = "v2"
			fields = secretCaptureFunctionV2Fields
		}
		path = strings.Join(strings.Split(path, "/")[:2], "/") + "/locations/-/functions"
		q.Set("pageSize", "100")
		q.Set("fields", "functions("+fields+"),nextPageToken,unreachable")
	case "composer_config":
		if host != "composer.googleapis.com" || !valid(regional+`environments/`+id) {
			return "", nil
		}
		q.Set("fields", viewerComposerFields)
	case "dataflow_options", "dataflow_config":
		if host != "dataflow.googleapis.com" || !valid(regional+`jobs/`+id) {
			return "", nil
		}
		version = "v1b3"
		q.Set("view", "JOB_VIEW_ALL")
		q.Set("fields", viewerDataflowFields)
	case "scheduler_config", "scheduler_headers":
		if host != "cloudscheduler.googleapis.com" || !valid(regional+`jobs/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "100")
		q.Set("fields", secretCaptureSchedulerFields)
	case "notebook_metadata", "workbench_metadata":
		if host != "notebooks.googleapis.com" || !valid(regional+`instances/`+id) {
			return "", nil
		}
		version = "v2"
		q.Set("fields", notebookGetFields)
	case "datafusion_options":
		if host != "datafusion.googleapis.com" || !valid(regional+`instances/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "100")
		q.Set("fields", dataFusionInstancesFields)
	case "dataproc_metadata", "dataproc_properties", "dataproc_args", "dataproc_query":
		if host != "dataproc.googleapis.com" || !valid(`projects/`+id+`/(regions|locations)/[a-z][a-z0-9-]*/(clusters|jobs|batches|workflowTemplates)/`+id) {
			return "", nil
		}
		p := strings.Split(path, "/")
		fields := map[string]string{"clusters": dataprocClusterSecretFields, "jobs": dataprocJobSecretFields, "batches": dataprocBatchSecretFields, "workflowTemplates": dataprocTemplateSecretFields}[p[4]]
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "100")
		q.Set("fields", fields)
	case "vertex_job_config", "vertex_pipeline_config", "vertex_pipeline_parameters":
		if host != "aiplatform.googleapis.com" || !valid(regional+`(customJobs|pipelineJobs)/`+id) {
			return "", nil
		}
		p := strings.Split(path, "/")
		if s.Location != "" && s.Location != p[3] {
			return "", nil
		}
		host = p[3] + "-aiplatform.googleapis.com"
		fields := "name,displayName,labels,state,createTime,startTime,endTime,updateTime,encryptionSpec,jobSpec"
		if p[4] == "pipelineJobs" {
			fields = "name,displayName,labels,state,createTime,startTime,endTime,updateTime,encryptionSpec,pipelineSpec,serviceAccount,network,reservedIpRanges,runtimeConfig,templateUri,templateMetadata"
		}
		q.Set("fields", fields)
	case "secret_manager_annotations":
		if host != "secretmanager.googleapis.com" || !valid(`projects/`+id+`/secrets/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "1000")
		q.Set("fields", secretCaptureGlobalSecretFields)
	case "clouddeploy_parameters":
		if host != "clouddeploy.googleapis.com" || !valid(regional+`(deliveryPipelines/`+id+`(/releases/`+id+`)?|targets/`+id+`)`) {
			return "", nil
		}
		fields := cloudDeployPipelineFields
		if strings.Contains(path, "/releases/") {
			fields = cloudDeployReleaseFields
		} else if strings.Contains(path, "/targets/") {
			fields = cloudDeployTargetFields
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "100")
		q.Set("fields", fields)
	case "apphosting_env":
		if host != "firebaseapphosting.googleapis.com" || !valid(regional+`backends/`+id+`/builds/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("pageSize", "100")
		q.Set("fields", appHostingBuildFields)
	default:
		return "", nil
	}
	// Validate masks/methods with the same classifier used by live collection.
	endpoint := "https://" + host + "/" + version + "/" + path
	if _, err := viewerRequestPermissions("GET", endpoint, q); err != nil {
		return "", nil
	}
	return endpoint, q
}
