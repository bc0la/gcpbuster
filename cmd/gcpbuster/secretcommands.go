package main

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

// secretPullCommand is report text only. It never executes a command, follows
// a referenced URL or contacts a credential issuer/provider. Commands use the
// operator's existing gcloud session to repeat an approved configuration read.
func secretPullCommand(sample inventory.SecretSample) string {
	if sample.SourceType == "apigee_bundle_config" {
		endpoint, q := inventory.ApigeeSecretRefetchRequest(sample)
		if endpoint == "" {
			return ""
		}
		if _, err := inventory.ViewerRequestPermissions("GET", endpoint, q); err != nil {
			return ""
		}
		u, _ := url.Parse(endpoint)
		u.RawQuery = q.Encode()
		return `curl --fail --silent --show-error --request GET --header "Authorization: Bearer $(gcloud auth print-access-token)" ` + secretShellQuote(u.String())
	}
	if sample.SourceType == "api_key_value" {
		name := strings.TrimPrefix(sample.Resource, "//apikeys.googleapis.com/")
		if regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/global/keys/[A-Za-z0-9_-]+$`).MatchString(name) && strings.HasPrefix(sample.Resource, "//apikeys.googleapis.com/") && (sample.Location == "" || sample.Location == "global") {
			// Official CLI supports project IDs and resolves the canonical API
			// identity itself; do not invent a project number for the curl URI.
			return "gcloud services api-keys get-key-string " + secretShellQuote(name) + " --location='global' --format='json'"
		}
		return ""
	}
	if body := inventory.SecretLogRefetchBody(sample); body != "" {
		return `curl --fail --silent --show-error --request POST --header "Authorization: Bearer $(gcloud auth print-access-token)" --header 'Content-Type: application/json' --data-binary ` + secretShellQuote(body) + ` 'https://logging.googleapis.com/v2/entries:list'`
	}
	endpoint, query := secretRefetchRequest(sample)
	if endpoint == "" {
		return ""
	}
	if _, err := inventory.ViewerRequestPermissions("GET", endpoint, query); err != nil {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	u.RawQuery = query.Encode()
	return `curl --fail --silent --show-error --request GET --header "Authorization: Bearer $(gcloud auth print-access-token)" ` + secretShellQuote(u.String())
}

// DNS response-policy API methods address user-assigned names, whereas captured
// asset identities preserve numeric IDs. Resolve only from the already scoped
// inventory, never infer a name or make an additional request during reporting.
func secretPullCommandFromAssets(sample inventory.SecretSample, assets []inventory.Asset) string {
	if sample.SourceType == "datafusion_connection_config" || sample.SourceType == "datafusion_pipeline_config" {
		endpoint := inventory.DataFusionManualRefetchURL(sample, assets)
		if endpoint == "" {
			return ""
		}
		return `curl --fail --silent --show-error --request GET --header "Authorization: Bearer $(gcloud auth print-access-token)" ` + secretShellQuote(endpoint)
	}
	if sample.SourceType != "dns_record_config" {
		return secretPullCommand(sample)
	}
	parts := regexp.MustCompile(`^(//dns\.googleapis\.com/projects/[A-Za-z0-9_-]+/responsePolicies/)([0-9]+)(/rules/[A-Za-z0-9_-]+)$`).FindStringSubmatch(sample.Resource)
	if len(parts) != 4 {
		return secretPullCommand(sample)
	}
	name := ""
	for _, asset := range assets {
		if asset.Type != "dns.googleapis.com/ResponsePolicy" || asset.Name != parts[1]+parts[2] {
			continue
		}
		candidate := inventory.Str(asset.Resource.Data["responsePolicyName"])
		if !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(candidate) {
			return ""
		}
		if name != "" && name != candidate {
			return ""
		}
		name = candidate
	}
	if name == "" {
		return ""
	}
	sample.Resource = parts[1] + name + parts[3]
	return secretPullCommand(sample)
}

func secretShellQuote(text string) string {
	return "'" + strings.ReplaceAll(text, "'", "'\"'\"'") + "'"
}

func secretSourceRevision(sample inventory.SecretSample) string {
	if sample.SourceType == "apigee_bundle_config" {
		if endpoint, _ := inventory.ApigeeSecretRefetchRequest(sample); endpoint != "" {
			return sample.Resource[strings.LastIndex(sample.Resource, "/")+1:]
		}
	}
	if sample.SourceType == "workflow_revision_definition" || sample.SourceType == "workflow_revision_env" {
		if endpoint, _ := inventory.SecretRefetchRequest(sample); endpoint == "" {
			return ""
		}
		parts := regexp.MustCompile(`^revisions\[([0-9]{6}-[a-f0-9]{3})\]\.`).FindStringSubmatch(sample.Path)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	if sample.SourceType == "run_revision_config" {
		if endpoint, _ := inventory.SecretRefetchRequest(sample); endpoint == "" {
			return ""
		}
		return sample.Resource[strings.LastIndex(sample.Resource, "/")+1:]
	}
	return ""
}

func secretRefetchInstruction(sample inventory.SecretSample) string {
	if sample.SourceType == "apigee_bundle_config" {
		return "Manual Viewer configuration read only. Download the exact revision bundle into a private file and extract only the reviewed XML member named by source_field using a safe bounded ZIP reader. Do not execute bundle code, follow configured URLs, or invoke or validate credentials. The saved XML source is assessment-time evidence; extraction indices refer to text leaves in document order."
	}
	return "Manual configuration read only. Use the intended Viewer identity, locate the exact source and field, and follow nextPageToken for collection reads. A refetch can differ from the saved assessment-time source. Do not invoke or validate the credential."
}

func secretRefetchRequest(sample inventory.SecretSample) (string, url.Values) {
	// Inputs are evidence, not trusted shell arguments. Reject URI escaping,
	// traversal, query injection, callbacks and arbitrary hosts before routing.
	if !strings.HasPrefix(sample.Resource, "//") || strings.ContainsAny(sample.Resource, "%?#\\\x00\r\n\t '") || strings.Contains(sample.Resource, "..") {
		return "", nil
	}
	pieces := strings.SplitN(strings.TrimPrefix(sample.Resource, "//"), "/", 2)
	if len(pieces) != 2 {
		return "", nil
	}
	host, path := pieces[0], pieces[1]
	q := url.Values{}
	match := func(pattern string) bool { return regexp.MustCompile("^" + pattern + "$").MatchString(path) }
	const id = `[A-Za-z0-9_-]+`
	const regional = `projects/` + id + `/locations/([a-z][a-z0-9-]*)/`
	switch sample.SourceType {
	case "parameter_template_raw":
		if host != "parametermanager.googleapis.com" || !match(regional+`templates/`+id+`/versions/`+id) {
			return "", nil
		}
		region := strings.Split(path, "/")[3]
		if sample.Location != "" && sample.Location != region {
			return "", nil
		}
		q.Set("fields", "name,payload(data)")
	case "parameter_manager_raw":
		if host != "parametermanager.googleapis.com" || !match(regional+`parameters/`+id+`/versions/`+id) {
			return "", nil
		}
		region := strings.Split(path, "/")[3]
		if sample.Location != "" && sample.Location != region {
			return "", nil
		}
		if region != "global" {
			host = "parametermanager." + region + ".rep.googleapis.com"
		}
		q.Set("view", "FULL")
		q.Set("fields", "name,disabled,payload(data)")
	case "deployment_manager_manifest":
		if host != "deploymentmanager.googleapis.com" || !match(`projects/`+id+`/global/deployments/`+id+`/manifests/`+id) {
			return "", nil
		}
		host = "www.googleapis.com"
		q.Set("fields", "name,selfLink,config(content),imports(content),expandedConfig,layout")
		return "https://" + host + "/deploymentmanager/v2/" + path, q
	case "workflow_definition", "workflow_env":
		if host != "workflows.googleapis.com" || !match(regional+`workflows/`+id) {
			return "", nil
		}
		q.Set("fields", "name,revisionId,state,createTime,updateTime,serviceAccount,sourceContents,userEnvVars,labels,callLogLevel,cryptoKeyName")
	case "workflow_execution":
		if host != "workflowexecutions.googleapis.com" || !match(regional+`workflows/`+id+`/executions/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("fields", "executions(name,argument,result,error(payload)),nextPageToken")
		q.Set("view", "FULL")
		q.Set("pageSize", "100")
	case "appengine_env", "appengine_build_env":
		if host != "appengine.googleapis.com" || !match(`apps/`+id+`/services/`+id+`/versions/`+id) {
			return "", nil
		}
		q.Set("fields", "name,id,runtime,env,servingStatus,serviceAccount,createTime,vm,threadsafe,appEngineApis,network(name,subnetworkName,instanceIpMode,sessionAffinity),vpcAccessConnector(name,egressSetting),envVariables,buildEnvVariables")
	case "api_key_value":
		if host != "apikeys.googleapis.com" || !match(`projects/[0-9]+/locations/global/keys/`+id) {
			return "", nil
		}
		path += "/keyString"
		q.Set("fields", "keyString")
		return "https://" + host + "/v2/" + path, q
	case "run_config", "run_job_config", "run_context":
		collection, fields := "services", "name,uid,createTime,updateTime,uri,ingress,invokerIamDisabled,iapEnabled,template,traffic,labels,annotations"
		if sample.SourceType == "run_job_config" || sample.SourceType == "run_context" && strings.Contains(path, "/jobs/") {
			collection = "jobs"
			fields = "name,uid,createTime,updateTime,template,labels,annotations"
		}
		if host != "run.googleapis.com" || !match(regional+collection+`/`+id) {
			return "", nil
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("fields", collection+"("+fields+"),nextPageToken,unreachable")
		q.Set("pageSize", "100")
		return "https://" + host + "/v2/" + path, q
	case "cloud_build_config":
		if host != "cloudbuild.googleapis.com" || !match(regional+`(builds|triggers)/`+id) {
			return "", nil
		}
		collection := strings.Split(path, "/")[4]
		fields := "id,name,projectId,status,createTime,startTime,finishTime,serviceAccount,steps,options,substitutions,source,sourceProvenance,availableSecrets,secrets,images,tags,logsBucket,logUrl,timeout"
		if collection == "triggers" {
			fields = "id,resourceName,name,description,createTime,disabled,serviceAccount,build,substitutions,filename,gitFileSource,sourceToBuild,triggerTemplate,github,repositoryEventConfig,bitbucketServerTriggerConfig,gitlabEnterpriseEventsConfig,includedFiles,ignoredFiles,filter,approvalConfig"
		}
		path = path[:strings.LastIndex(path, "/")]
		q.Set("fields", collection+"("+fields+"),nextPageToken")
		q.Set("pageSize", "100")
	default:
		return inventory.SecretRefetchRequest(sample)
	}
	if sample.Location != "" && strings.Contains(path, "/locations/") && strings.Split(path, "/")[3] != sample.Location {
		return "", nil
	}
	return "https://" + host + "/v1/" + path, q
}
