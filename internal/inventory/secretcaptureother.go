package inventory

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// CaptureInventory inspects explicitly supplied or retained configuration only.
// It does not establish live authorization for offline data or follow references.
func (c *SecretCapture) CaptureInventory(assets []Asset) {
	if c == nil {
		return
	}
	for _, a := range assets {
		if c.captureOfflineParameter(a) {
			continue
		}
		if c.captureOfflineCDAP(a) {
			continue
		}
		if c.captureOfflineDNS(a) {
			continue
		}
		if c.captureOfflineSQLFlags(a) {
			continue
		}
		if a.Type == "appengine.googleapis.com/Version" {
			if regexp.MustCompile(`^//appengine\.googleapis\.com/apps/[A-Za-z0-9_-]+/services/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
				c.CaptureStringMap("appengine_env", a.Name, "", "envVariables", a.Resource.Data["envVariables"])
				c.CaptureStringMap("appengine_build_env", a.Name, "", "buildEnvVariables", a.Resource.Data["buildEnvVariables"])
			}
			continue
		}
		if a.Type == ServiceConfigType {
			d := a.Resource.Data
			service, id := Str(d["name"]), Str(d["id"])
			if viewerResourceName.MatchString(Str(d["producerProjectId"])) && service != "" && id != "" && a.Name == "//servicemanagement.googleapis.com/services/"+service+"/configs/"+id && !strings.ContainsAny(service+id, "/?#\\") {
				c.captureServiceConfig(a.Name, d)
			}
			continue
		}
		parts := strings.Split(strings.TrimPrefix(a.Name, "//"), "/")
		if len(parts) < 3 || !strings.HasPrefix(a.Name, "//") || parts[1] != "projects" || !viewerResourceName.MatchString(parts[2]) {
			continue
		}
		host := strings.SplitN(a.Type, "/", 2)[0]
		if parts[0] != host {
			continue
		}
		if strings.Contains(a.Name, "..") || strings.ContainsAny(a.Name, "?#\\") {
			continue
		}
		switch a.Type {
		case "parametermanager.googleapis.com/TemplateVersion":
			if len(parts) == 9 && parts[3] == "locations" && viewerLocation.MatchString(parts[4]) && parts[5] == "templates" && viewerKeyResourceID.MatchString(parts[6]) && parts[7] == "versions" && viewerKeyResourceID.MatchString(parts[8]) && a.Resource.Data["payload"] != nil {
				client := &Client{SecretCapture: c}
				if client.captureParameterTemplateVersion(a.Resource.Data, strings.TrimPrefix(a.Name, "//parametermanager.googleapis.com/"), parts[4], parts[2], "projects/"+parts[2]) != nil {
					c.Add(SecretSample{})
				}
			}
		case "datafusion.googleapis.com/Instance":
			if len(parts) == 7 && parts[3] == "locations" && viewerLocation.MatchString(parts[4]) && parts[5] == "instances" && viewerResourceName.MatchString(parts[6]) {
				c.CaptureStringMap("datafusion_options", a.Name, a.Resource.Location, "options", a.Resource.Data["options"])
			}
		case "clouddeploy.googleapis.com/DeliveryPipeline", "clouddeploy.googleapis.com/Target":
			collection := "deliveryPipelines"
			if a.Type == "clouddeploy.googleapis.com/Target" {
				collection = "targets"
			}
			if len(parts) == 7 && parts[3] == "locations" && viewerLocation.MatchString(parts[4]) && parts[5] == collection && viewerResourceName.MatchString(parts[6]) {
				c.captureCloudDeploy(a)
			}
		case "clouddeploy.googleapis.com/Release":
			if len(parts) == 9 && parts[3] == "locations" && viewerLocation.MatchString(parts[4]) && parts[5] == "deliveryPipelines" && viewerResourceName.MatchString(parts[6]) && parts[7] == "releases" && viewerResourceName.MatchString(parts[8]) {
				c.captureCloudDeployRelease(a)
			}
		case "firebaseapphosting.googleapis.com/Build":
			if len(parts) == 9 && parts[3] == "locations" && viewerLocation.MatchString(parts[4]) && parts[5] == "backends" && viewerResourceName.MatchString(parts[6]) && parts[7] == "builds" && viewerResourceName.MatchString(parts[8]) {
				c.captureAppHosting(a)
			}
		case "secretmanager.googleapis.com/Secret":
			if regexp.MustCompile(`^//secretmanager\.googleapis\.com/projects/[^/]+/(locations/[a-z0-9-]+/)?secrets/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
				c.CaptureStringMap("secret_manager_annotations", a.Name, a.Resource.Location, "annotations", a.Resource.Data["annotations"])
			}
		case "aiplatform.googleapis.com/PipelineJob":
			if regexp.MustCompile(`^//aiplatform\.googleapis\.com/projects/[^/]+/locations/[a-z0-9-]+/pipelineJobs/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
				c.capturePipeline(a)
			}
		case "apigateway.googleapis.com/ApiConfig":
			if regexp.MustCompile(`^//apigateway\.googleapis\.com/projects/[^/]+/locations/global/apis/[A-Za-z0-9_-]+/configs/[A-Za-z0-9_-]+$`).MatchString(a.Name) && a.Resource.Data["openapiDocuments"] != nil {
				c.captureOpenAPI(a.Name, a.Resource.Data)
			}
		case "run.googleapis.com/Service", "run.googleapis.com/Job", "cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function":
			collection := map[string]string{"run.googleapis.com/Service": "services", "run.googleapis.com/Job": "jobs", "cloudfunctions.googleapis.com/CloudFunction": "functions", "cloudfunctions.googleapis.com/Function": "functions"}[a.Type]
			if len(parts) == 7 && parts[3] == "locations" && parts[5] == collection && viewerServerlessRegion.MatchString(parts[4]) && viewerResourceName.MatchString(parts[6]) {
				c.captureServerless(a)
			}
		case "cloudbuild.googleapis.com/Build", "cloudbuild.googleapis.com/BuildTrigger":
			collection := "builds"
			if a.Type == "cloudbuild.googleapis.com/BuildTrigger" {
				collection = "triggers"
			}
			if len(parts) == 7 && parts[3] == "locations" && parts[5] == collection && viewerLocation.MatchString(parts[4]) && viewerResourceName.MatchString(parts[6]) {
				c.captureBuild(a)
			}
		case "compute.googleapis.com/Instance":
			if len(parts) == 7 && parts[3] == "zones" && parts[5] == "instances" {
				c.captureMetadata("compute_instance_metadata", a.Name, a.Resource.Location, "metadata", a.Resource.Data["metadata"])
			}
		case "compute.googleapis.com/Project":
			if len(parts) == 3 {
				c.captureMetadata("compute_project_metadata", a.Name, "", "commonInstanceMetadata", a.Resource.Data["commonInstanceMetadata"])
			}
		case "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/MachineImage", "composer.googleapis.com/Environment", "cloudscheduler.googleapis.com/Job", "aiplatform.googleapis.com/CustomJob", "dataflow.googleapis.com/Job":
			pattern := map[string]string{"compute.googleapis.com/InstanceTemplate": `^//compute\.googleapis\.com/projects/[^/]+/(global|regions/[a-z0-9-]+)/instanceTemplates/[A-Za-z0-9_-]+$`, "compute.googleapis.com/MachineImage": `^//compute\.googleapis\.com/projects/[^/]+/global/machineImages/[A-Za-z0-9_-]+$`, "composer.googleapis.com/Environment": `^//composer\.googleapis\.com/projects/[^/]+/locations/[a-z0-9-]+/environments/[A-Za-z0-9_-]+$`, "cloudscheduler.googleapis.com/Job": `^//cloudscheduler\.googleapis\.com/projects/[^/]+/locations/[a-z0-9-]+/jobs/[A-Za-z0-9._~-]+$`, "aiplatform.googleapis.com/CustomJob": `^//aiplatform\.googleapis\.com/projects/[^/]+/locations/[a-z0-9-]+/customJobs/[0-9]+$`, "dataflow.googleapis.com/Job": `^//dataflow\.googleapis\.com/projects/[^/]+/locations/[a-z0-9-]+/jobs/[A-Za-z0-9_-]+$`}[a.Type]
			if regexp.MustCompile(pattern).MatchString(a.Name) {
				c.captureOther(a)
			}
		case "workflows.googleapis.com/Workflow":
			if len(parts) == 7 && parts[5] == "workflows" {
				if v, ok := a.Resource.Data["sourceContents"].(string); ok && v != "" && v != "[REDACTED]" {
					c.Add(SecretSample{SourceType: "workflow_definition", Resource: a.Name, Location: a.Resource.Location, Path: "sourceContents", Data: []byte(v)})
				}
				c.CaptureStringMap("workflow_env", a.Name, a.Resource.Location, "userEnvVars", a.Resource.Data["userEnvVars"])
			}
		}
	}
}

const secretCaptureSchedulerFields = "jobs(name,description,schedule,timeZone,state,httpTarget(uri,httpMethod,headers,oauthToken(serviceAccountEmail,scope),oidcToken(serviceAccountEmail,audience)),appEngineHttpTarget(relativeUri,httpMethod,headers,appEngineRouting)),nextPageToken"
const secretCaptureTemplateFields = "name,selfLink,id,creationTimestamp,properties"
const secretCaptureMachineImageFields = "name,selfLink,id,creationTimestamp,status,instanceProperties,sourceInstance"
const secretCaptureGlobalSecretFields = "secrets(name,createTime,expireTime,ttl,replication,rotation,topics,labels,annotations,versionAliases,etag,versionDestroyTtl),nextPageToken"

var secretCaptureRegionalSecretFields = strings.Replace(viewerRegionalSecretFields, "secrets(", "secrets(annotations,", 1)

func secretCaptureQueryMask(u *url.URL, q url.Values) error {
	if !q.Has("fields") {
		return nil
	}
	var want string
	if regexp.MustCompile(`^secretmanager\.[a-z0-9-]+\.rep\.googleapis\.com$`).MatchString(u.Host) && regexp.MustCompile(`^/v1/projects/[^/]+/locations/[^/]+/secrets$`).MatchString(u.Path) {
		want = secretCaptureRegionalSecretFields
		if q.Get("fields") == viewerRegionalSecretFields {
			return nil
		}
	}
	for _, s := range []struct{ host, path, mask string }{
		{"compute.googleapis.com", `^/compute/v1/projects/[^/]+$`, secretCaptureComputeProjectFields},
		{"secretmanager.googleapis.com", `^/v1/projects/[^/]+/secrets$`, secretCaptureGlobalSecretFields},
		{"compute.googleapis.com", `^/compute/v1/projects/[^/]+/aggregated/instances$`, "items/*/instances(" + secretCaptureComputeInstanceFields + "),items/*/warning,items/*/error,nextPageToken,warning,unreachables"},
		{"compute.googleapis.com", `^/compute/v1/projects/[^/]+/aggregated/instanceTemplates$`, "items/*/instanceTemplates(" + secretCaptureTemplateFields + "),items/*/warning,items/*/error,nextPageToken,warning,unreachables"},
		{"compute.googleapis.com", `^/compute/v1/projects/[^/]+/global/machineImages$`, "items(" + secretCaptureMachineImageFields + "),nextPageToken,warning"},
		{"run.googleapis.com", `^/v2/projects/[^/]+/locations/[^/]+/services$`, "services(" + secretCaptureRunServiceFields + "),nextPageToken,unreachable"},
		{"run.googleapis.com", `^/v2/projects/[^/]+/locations/[^/]+/jobs$`, "jobs(" + secretCaptureRunJobFields + "),nextPageToken,unreachable"},
		{"cloudfunctions.googleapis.com", `^/v1/projects/[^/]+/locations/-/functions$`, "functions(" + secretCaptureFunctionV1Fields + "),nextPageToken,unreachable"},
		{"cloudfunctions.googleapis.com", `^/v2/projects/[^/]+/locations/-/functions$`, "functions(" + secretCaptureFunctionV2Fields + "),nextPageToken,unreachable"},
		{"cloudbuild.googleapis.com", `^/v1/projects/[^/]+/locations/[^/]+/builds$`, "builds(" + secretCaptureBuildFields + "),nextPageToken"},
		{"cloudbuild.googleapis.com", `^/v1/projects/[^/]+/locations/[^/]+/triggers$`, "triggers(" + secretCaptureTriggerFields + "),nextPageToken"},
		{"workflows.googleapis.com", `^/v1/projects/[^/]+/locations/[^/]+/workflows/[^/]+$`, secretCaptureWorkflowFields},
		{"cloudscheduler.googleapis.com", `^/v1/projects/[^/]+/locations/[^/]+/jobs$`, secretCaptureSchedulerFields},
	} {
		if u.Host == s.host && regexp.MustCompile(s.path).MatchString(u.Path) {
			want = s.mask
			break
		}
	}
	if want != "" && (len(q["fields"]) != 1 || q.Get("fields") != want) {
		return fmt.Errorf("viewer-only policy: unreviewed configuration capture field mask")
	}
	return nil
}

func (c *SecretCapture) captureOther(a Asset) {
	if c == nil {
		return
	}
	d := a.Resource.Data
	switch a.Type {
	case "compute.googleapis.com/InstanceTemplate":
		c.captureMetadata("compute_template_metadata", a.Name, a.Resource.Location, "properties.metadata", Get(d, "properties", "metadata"))
	case "compute.googleapis.com/MachineImage":
		c.captureMetadata("compute_machine_image_metadata", a.Name, a.Resource.Location, "instanceProperties.metadata", Get(d, "instanceProperties", "metadata"))
	case "composer.googleapis.com/Environment":
		for _, field := range []string{"envVariables", "airflowConfigOverrides", "pypiPackages"} {
			c.CaptureStringMap("composer_config", a.Name, a.Resource.Location, "config.softwareConfig."+field, Get(d, "config", "softwareConfig", field))
		}
	case "cloudscheduler.googleapis.com/Job":
		for target, field := range map[string]string{"httpTarget": "uri", "appEngineHttpTarget": "relativeUri"} {
			if v, ok := Get(d, target, field).(string); ok && v != "" {
				c.Add(SecretSample{SourceType: "scheduler_config", Resource: a.Name, Location: a.Resource.Location, Path: target + "." + field, Data: []byte(v)})
			}
			c.CaptureStringMap("scheduler_headers", a.Name, a.Resource.Location, target+".headers", Get(d, target, "headers"))
		}
	case "aiplatform.googleapis.com/CustomJob":
		workers, _ := Get(d, "jobSpec", "workerPoolSpecs").([]any)
		for i, w := range workers {
			worker := Obj(w)
			base := fmt.Sprintf("jobSpec.workerPoolSpecs[%d]", i)
			container := Obj(worker["containerSpec"])
			c.captureContainers("vertex_job_config", a.Name, a.Resource.Location, base+".containerSpec", []any{container})
			python := Obj(worker["pythonPackageSpec"])
			for _, field := range []string{"args"} {
				rows, _ := python[field].([]any)
				for j, r := range rows {
					if v, ok := r.(string); ok && v != "" {
						c.Add(SecretSample{SourceType: "vertex_job_config", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("%s.pythonPackageSpec.%s[%d]", base, field, j), Data: []byte(v)})
					}
				}
			}
		}
	case "dataflow.googleapis.com/Job":
		c.captureConfigurationTree("dataflow_config", a, "environment.sdkPipelineOptions", Get(d, "environment", "sdkPipelineOptions"))
		steps, _ := d["steps"].([]any)
		for i, step := range steps {
			c.captureConfigurationTree("dataflow_config", a, fmt.Sprintf("steps[%d].properties", i), Get(Obj(step), "properties"))
		}
	case "aiplatform.googleapis.com/PipelineJob":
		c.capturePipeline(a)
	}
}
