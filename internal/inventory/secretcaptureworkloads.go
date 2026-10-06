package inventory

import (
	"fmt"
	"strings"
)

const secretCaptureComputeProjectFields = "name,id,selfLink,commonInstanceMetadata(items(key,value)),defaultServiceAccount"
const secretCaptureComputeInstanceFields = "id,name,selfLink,zone,status,machineType,creationTimestamp,metadata(items(key,value)),serviceAccounts,tags,networkInterfaces,disks,shieldedInstanceConfig,confidentialInstanceConfig"
const secretCaptureRunServiceFields = "name,uid,createTime,updateTime,uri,ingress,invokerIamDisabled,iapEnabled,template,traffic,labels,annotations"
const secretCaptureRunJobFields = "name,uid,createTime,updateTime,template,labels,annotations"
const secretCaptureFunctionV1Fields = "name,status,runtime,serviceAccountEmail,environmentVariables,buildEnvironmentVariables,httpsTrigger,eventTrigger,ingressSettings,vpcConnector,vpcConnectorEgressSettings,secretEnvironmentVariables,secretVolumes,sourceArchiveUrl,sourceRepository,labels"
const secretCaptureFunctionV2Fields = "name,state,environment,buildConfig,serviceConfig,eventTrigger,labels"
const secretCaptureBuildFields = "id,name,projectId,status,createTime,startTime,finishTime,serviceAccount,steps,options,substitutions,source,sourceProvenance,availableSecrets,secrets,images,tags,logsBucket,logUrl,timeout"
const secretCaptureTriggerFields = "id,resourceName,name,description,createTime,disabled,serviceAccount,build,substitutions,filename,gitFileSource,sourceToBuild,triggerTemplate,github,repositoryEventConfig,bitbucketServerTriggerConfig,gitlabEnterpriseEventsConfig,includedFiles,ignoredFiles,filter,approvalConfig"
const secretCaptureWorkflowFields = "name,revisionId,state,createTime,updateTime,serviceAccount,sourceContents,userEnvVars,labels,callLogLevel,cryptoKeyName"

func (c *SecretCapture) captureMetadata(source, resource, location, path string, v any) {
	if c == nil {
		return
	}
	rows, _ := Get(Obj(v), "items").([]any)
	for i, row := range rows {
		d := Obj(row)
		key, ok := d["key"].(string)
		value, vok := d["value"].(string)
		if ok && vok && key != "" && value != "" {
			c.Add(SecretSample{SourceType: source, Resource: resource, Location: location, Path: fmt.Sprintf("%s.items[%d].value", path, i), Data: []byte(key + "=" + value)})
		}
	}
}

func (c *SecretCapture) captureContainers(source, resource, location, path string, v any) {
	if c == nil {
		return
	}
	rows, _ := v.([]any)
	for i, row := range rows {
		d := Obj(row)
		base := fmt.Sprintf("%s[%d]", path, i)
		for _, field := range []string{"command", "args"} {
			entries, _ := d[field].([]any)
			for j, e := range entries {
				if value, ok := e.(string); ok && value != "" {
					c.Add(SecretSample{SourceType: source, Resource: resource, Location: location, Path: fmt.Sprintf("%s.%s[%d]", base, field, j), Data: []byte(value)})
				}
			}
		}
		env, _ := d["env"].([]any)
		for j, e := range env {
			entry := Obj(e)
			name, nok := entry["name"].(string)
			value, vok := entry["value"].(string)
			if nok && vok && name != "" && value != "[REDACTED]" && entry["valueSource"] == nil && entry["valueFrom"] == nil {
				c.Add(SecretSample{SourceType: source, Resource: resource, Location: location, Path: fmt.Sprintf("%s.env[%d].value", base, j), Data: []byte(name + "=" + value)})
			}
		}
	}
}

func (c *SecretCapture) captureServerless(a Asset) {
	if c == nil {
		return
	}
	d := a.Resource.Data
	switch a.Type {
	case "run.googleapis.com/Service":
		c.captureContainers("run_config", a.Name, a.Resource.Location, "template.containers", Get(d, "template", "containers"))
		c.captureRunContext(a, "template")
	case "run.googleapis.com/Job":
		c.captureContainers("run_job_config", a.Name, a.Resource.Location, "template.template.containers", Get(d, "template", "template", "containers"))
		c.captureRunContext(a, "template.template")
	case "cloudfunctions.googleapis.com/CloudFunction":
		c.CaptureStringMap("function_env", a.Name, a.Resource.Location, "environmentVariables", d["environmentVariables"])
		c.CaptureStringMap("function_build_env", a.Name, a.Resource.Location, "buildEnvironmentVariables", d["buildEnvironmentVariables"])
	case "cloudfunctions.googleapis.com/Function":
		c.CaptureStringMap("function_env", a.Name, a.Resource.Location, "serviceConfig.environmentVariables", Get(d, "serviceConfig", "environmentVariables"))
		c.CaptureStringMap("function_build_env", a.Name, a.Resource.Location, "buildConfig.environmentVariables", Get(d, "buildConfig", "environmentVariables"))
	}
}

// Context inventory mirrors task-definition image/role metadata, not image
// retrieval or secret scanning of image contents.
func (c *SecretCapture) captureRunContext(a Asset, prefix string) {
	parts := strings.Split(prefix, ".")
	template := Obj(Get(a.Resource.Data, parts...))
	if account, ok := template["serviceAccount"].(string); ok {
		c.Add(SecretSample{SourceType: "run_context", Resource: a.Name, Location: a.Resource.Location, Path: prefix + ".serviceAccount", Data: []byte("serviceAccount=" + account)})
	}
	rows, _ := template["containers"].([]any)
	for i, row := range rows {
		if image, ok := Obj(row)["image"].(string); ok {
			c.Add(SecretSample{SourceType: "run_context", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("%s.containers[%d].image", prefix, i), Data: []byte("image=" + image)})
		}
	}
}

// Retained revisions use root-level container/identity fields, unlike the
// current Service template. Capture the already-read context without fetching
// images or impersonating the configured service account.
func (c *SecretCapture) captureRunRevisionContext(resource, location string, d Object) {
	if c == nil {
		return
	}
	if account, ok := d["serviceAccount"].(string); ok {
		c.Add(SecretSample{SourceType: "run_revision_config", Resource: resource, Location: location, Path: "serviceAccount", Data: []byte("serviceAccount=" + account)})
	}
	rows, _ := d["containers"].([]any)
	for i, row := range rows {
		if image, ok := Obj(row)["image"].(string); ok {
			c.Add(SecretSample{SourceType: "run_revision_config", Resource: resource, Location: location, Path: fmt.Sprintf("containers[%d].image", i), Data: []byte("image=" + image)})
		}
	}
}

func (c *SecretCapture) captureBuild(a Asset) {
	if c == nil {
		return
	}
	d := a.Resource.Data
	prefix := ""
	if a.Type == "cloudbuild.googleapis.com/BuildTrigger" {
		d = Obj(d["build"])
		prefix = "build."
	}
	c.CaptureStringMap("cloud_build_config", a.Name, a.Resource.Location, prefix+"substitutions", d["substitutions"])
	steps, _ := d["steps"].([]any)
	for i, row := range steps {
		step := Obj(row)
		for _, field := range []string{"env", "args"} {
			entries, _ := step[field].([]any)
			for j, e := range entries {
				if v, ok := e.(string); ok && v != "" {
					c.Add(SecretSample{SourceType: "cloud_build_config", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("%ssteps[%d].%s[%d]", prefix, i, field, j), Data: []byte(v)})
				}
			}
		}
		if v, ok := step["script"].(string); ok && v != "" {
			c.Add(SecretSample{SourceType: "cloud_build_config", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("%ssteps[%d].script", prefix, i), Data: []byte(v)})
		}
	}
	entries, _ := Get(d, "options", "env").([]any)
	for i, e := range entries {
		if v, ok := e.(string); ok && v != "" {
			c.Add(SecretSample{SourceType: "cloud_build_config", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("%soptions.env[%d]", prefix, i), Data: []byte(v)})
		}
	}
}
